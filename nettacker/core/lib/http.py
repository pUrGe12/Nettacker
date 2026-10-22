#!/usr/bin/env python

import asyncio
import atexit
import copy
import random
import re
import sys
import threading
import time

import aiohttp

from nettacker.core.lib.base import BaseEngine
from nettacker.core.utils.common import (
    get_http_header_key,
    get_http_header_value,
    replace_dependent_response,
    reverse_and_regex_condition,
)

if sys.platform != "win32":
    import uvloop

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


# One event loop runs in a dedicated background thread for the lifetime of the
# process and owns a single shared aiohttp.ClientSession. Worker threads submit
# their request coroutines onto that loop with run_coroutine_threadsafe, so every
# request reuses one connection pool (HTTP keep-alive) instead of building a
# throwaway event loop and a brand-new TCP/TLS connection per request.
_loop = None
_loop_lock = threading.Lock()
_session = None
_session_lock = threading.Lock()


def _get_loop():
    """Return the shared background event loop, starting it on first use."""
    global _loop
    if _loop is None:
        with _loop_lock:
            if _loop is None:
                loop = asyncio.new_event_loop()
                thread = threading.Thread(
                    target=loop.run_forever,
                    name="nettacker-http-loop",
                    daemon=True,
                )
                thread.start()
                _loop = loop
    return _loop


async def _new_session():
    # limit=0 leaves the number of simultaneous connections unbounded (the
    # worker thread pool already caps concurrency); keep-alive, on by default,
    # returns idle connections to the pool for reuse.
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
    return aiohttp.ClientSession(connector=connector)


def _get_session():
    """Return the shared ClientSession, creating it on the loop on first use."""
    global _session
    if _session is None:
        with _session_lock:
            if _session is None:
                loop = _get_loop()
                _session = asyncio.run_coroutine_threadsafe(_new_session(), loop).result()
    return _session


@atexit.register
def _close_shared_session():
    """Best-effort shutdown of the shared session and loop at process exit."""
    global _session, _loop
    if _session is not None and _loop is not None:
        try:
            asyncio.run_coroutine_threadsafe(_session.close(), _loop).result(timeout=5)
        except Exception:
            pass
        _session = None
    if _loop is not None:
        _loop.call_soon_threadsafe(_loop.stop)
        _loop = None


async def perform_request_action(action, request_options):
    """
    perform a single HTTP request and normalize the response into a dict

    Args:
        action: a bound aiohttp.ClientSession method (e.g. session.get, session.post)
        request_options: keyword arguments to pass to action (url, headers, etc.)

    Returns:
        a dict with reason, url, status_code, content, headers, and responsetime
    """
    start_time = time.time()
    async with action(**request_options) as response:
        return {
            "reason": response.reason,
            "url": str(response.url),
            "status_code": str(response.status),
            "content": await response.content.read(),
            "headers": dict(response.headers),
            "responsetime": time.time() - start_time,
        }


async def send_request(request_options, method, session):
    """
    dispatch a single request through an already-open aiohttp session

    Args:
        request_options: keyword arguments forwarded to perform_request_action
        method: the HTTP method name to call on the session (e.g. "get", "post")
        session: the aiohttp.ClientSession to send the request on

    Returns:
        the normalized response dict from perform_request_action
    """
    action = getattr(session, method, None)
    response = await asyncio.gather(
        *[asyncio.ensure_future(perform_request_action(action, request_options))]
    )
    return response[0]


def send_request_sync(request_options, method):
    """
    blocking entry point for worker threads: run send_request on the shared
    background loop against the shared session and wait for the result

    Args:
        request_options: keyword arguments forwarded to send_request
        method: the HTTP method name to call on the session (e.g. "get", "post")

    Returns:
        the normalized response dict from perform_request_action
    """
    loop = _get_loop()
    session = _get_session()
    return asyncio.run_coroutine_threadsafe(
        send_request(request_options, method, session), loop
    ).result()


def response_conditions_matched(sub_step, response):
    """
    check an HTTP response against a module step's configured conditions

    Evaluates each condition in sub_step["response"]["conditions"] (reason,
    status_code, content, url, headers, responsetime regex/comparison checks)
    against the actual response, then combines the per-condition results
    using the step's condition_type ("or"/"and") to decide whether the step
    as a whole matched.

    Args:
        sub_step: the module step definition, including response conditions
        response: the normalized response dict from perform_request_action,
            or a falsy value if the request failed

    Returns:
        a dict of matched condition results (with an optional "log" entry)
        if the step's conditions matched, otherwise an empty dict
    """
    if not response:
        return {}
    condition_type = sub_step["response"]["condition_type"]
    conditions = sub_step["response"]["conditions"]
    condition_results = {}
    for condition in conditions:
        if condition in ["reason", "status_code", "content", "url"]:
            regex = re.findall(re.compile(conditions[condition]["regex"]), response[condition])
            reverse = conditions[condition]["reverse"]
            condition_results[condition] = reverse_and_regex_condition(regex, reverse)
        if condition == "headers":
            # convert headers to case insensitive dict
            for key in response["headers"].copy():
                response["headers"][key.lower()] = response["headers"][key]
            condition_results["headers"] = {}
            for header in conditions["headers"]:
                reverse = conditions["headers"][header]["reverse"]
                try:
                    regex = re.findall(
                        re.compile(conditions["headers"][header]["regex"]),
                        response["headers"][header.lower()]
                        if header.lower() in response["headers"]
                        else False,
                    )
                    condition_results["headers"][header] = reverse_and_regex_condition(
                        regex, reverse
                    )
                except TypeError:
                    condition_results["headers"][header] = []
        if condition == "responsetime":
            if len(conditions[condition].split()) == 2 and conditions[condition].split()[0] in [
                "==",
                "!=",
                ">=",
                "<=",
                ">",
                "<",
            ]:
                exec(
                    "condition_results['responsetime'] = response['responsetime'] if ("
                    + "response['responsetime'] {0} float(conditions['responsetime'].split()[-1])".format(
                        conditions["responsetime"].split()[0]
                    )
                    + ") else []"
                )
            else:
                condition_results["responsetime"] = []
    if condition_type.lower() == "or":
        # if one of the values are matched, it will be a string or float object in the array
        # we count False in the array and if it's not all []; then we know one of the conditions
        # is matched.
        if (
            "headers" not in condition_results
            and (
                list(condition_results.values()).count([]) != len(list(condition_results.values()))
            )
        ) or (
            "headers" in condition_results
            and (
                len(list(condition_results.values()))
                + len(list(condition_results["headers"].values()))
                - list(condition_results.values()).count([])
                - list(condition_results["headers"].values()).count([])
                - 1
                != 0
            )
        ):
            if sub_step["response"].get("log", False):
                condition_results["log"] = sub_step["response"]["log"]
                if "response_dependent" in condition_results["log"]:
                    condition_results["log"] = replace_dependent_response(
                        condition_results["log"], condition_results
                    )
            return condition_results
        else:
            return {}
    if condition_type.lower() == "and":
        if [] in condition_results.values() or (
            "headers" in condition_results and [] in condition_results["headers"].values()
        ):
            return {}
        else:
            if sub_step["response"].get("log", False):
                condition_results["log"] = sub_step["response"]["log"]
                if "response_dependent" in condition_results["log"]:
                    condition_results["log"] = replace_dependent_response(
                        condition_results["log"], condition_results
                    )
            return condition_results
    return {}


class HttpEngine(BaseEngine):
    def run(
        self,
        sub_step,
        module_name,
        target,
        scan_id,
        options,
        process_number,
        module_thread_number,
        total_module_thread_number,
        request_number_counter,
        total_number_of_requests,
    ):
        """
        execute this module step's HTTP request against a target and process the result

        Applies custom/random-user-agent headers, resolves any
        dependent-on-temp-event substitutions, then sends the request via
        send_request_sync(...) with retries, and hands the response
        off to condition matching and event processing.

        Args:
            sub_step: the module step definition to execute
            module_name: the module this step belongs to
            target: the target being scanned
            scan_id: unique scan identifier
            options: all scan options
            process_number: index of the parent process, used for logging
            module_thread_number: index of this module's thread, used for logging
            total_module_thread_number: total threads running this module, used for logging
            request_number_counter: index of this request, used for logging
            total_number_of_requests: total requests for this step, used for logging

        Returns:
            the result of self.process_conditions(...) for this step
        """
        if options["http_header"] is not None:
            for header in options["http_header"]:
                key = get_http_header_key(header).strip()
                value = get_http_header_value(header)
                if value is not None:
                    sub_step["headers"][key] = value.strip()
                else:
                    sub_step["headers"][key] = ""
        backup_method = copy.deepcopy(sub_step["method"])
        backup_response = copy.deepcopy(sub_step["response"])
        backup_iterative_response_match = copy.deepcopy(
            sub_step["response"]["conditions"].get("iterative_response_match", None)
        )
        if options["user_agent"] == "random_user_agent":
            sub_step["headers"]["User-Agent"] = random.choice(options["user_agents"])
        del sub_step["method"]
        if "dependent_on_temp_event" in backup_response:
            temp_event = self.get_dependent_results_from_database(
                target,
                module_name,
                scan_id,
                backup_response["dependent_on_temp_event"],
            )
            sub_step = self.replace_dependent_values(sub_step, temp_event)
        backup_response = copy.deepcopy(sub_step["response"])
        del sub_step["response"]
        for _i in range(options["retries"]):
            try:
                response = send_request_sync(sub_step, backup_method)
                response["content"] = response["content"].decode(errors="ignore")
                break
            except Exception:
                response = []
        sub_step["method"] = backup_method
        sub_step["response"] = backup_response

        if backup_iterative_response_match is not None:
            backup_iterative_response_match = copy.deepcopy(
                sub_step["response"]["conditions"].get("iterative_response_match")
            )
            del sub_step["response"]["conditions"]["iterative_response_match"]

        sub_step["response"]["conditions_results"] = response_conditions_matched(
            sub_step, response
        )

        if backup_iterative_response_match is not None and (
            sub_step["response"]["conditions_results"]
            or sub_step["response"]["condition_type"] == "or"
        ):
            sub_step["response"]["conditions"][
                "iterative_response_match"
            ] = backup_iterative_response_match
            for key in sub_step["response"]["conditions"]["iterative_response_match"]:
                result = response_conditions_matched(
                    sub_step["response"]["conditions"]["iterative_response_match"][key],
                    response,
                )
                if result:
                    sub_step["response"]["conditions_results"][key] = result

        return self.process_conditions(
            sub_step,
            module_name,
            target,
            scan_id,
            options,
            response,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests,
        )
