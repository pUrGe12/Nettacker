import json
import time

import apsw

from nettacker import logger
from nettacker.api.helpers import structure
from nettacker.config import Config
from nettacker.core.messages import messages
from nettacker.database.models import HostsLog, Report, TempEvents

config = Config()
log = logger.get_logger()


def db_inputs(connection_type):
    """
    a function to determine the type of database the user wants to work with and
    selects the corresponding connection to the db

    Args:
        connection_type: type of db we are working with

    Returns:
        corresponding command to connect to the db
    """
    context = Config.db.as_dict()
    return {
        "postgres": "postgres+psycopg2://{username}:{password}@{host}:{port}/{name}".format(
            **context
        ),
        "mysql": "mysql://{username}:{password}@{host}:{port}/{name}".format(**context),
        "sqlite": "sqlite:///{name}".format(**context),
    }[connection_type]


def create_connection():
    """
    Create an APSW connection to the SQLite DB only bypassing db_inputs.
    """
    DB_PATH = config.db.as_dict()["name"]
    connection = apsw.Connection(DB_PATH)
    connection.setbusytimeout(int(config.settings.timeout)*100)
    cursor = connection.cursor()

    # Performance enhancing configurations. Put WAL cause that helps with concurrency
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    
    return connection, cursor


def send_submit_query(connection):
    """
    Commit queries with retry logic. After every try, the connection
    resets, so we must rollback. If it doesn't happen after a 100 times
    then that means, connection failed.
    """
    for _ in range(100):
        try:
            connection.execute("COMMIT")
            return True
        except Exception as e:
            connection.execute("ROLLBACK") 
            time.sleep(0.1)
        finally:
            connection.close()
    connection.close()
    log.warn(messages("database_connect_fail"))
    return False


def submit_report_to_db(event):
    """
    this function created to submit the generated reports into db, the
    files are not stored in db, just the path!

    Args:
        event: event log

    Returns:
        return True if submitted otherwise False
    """
    log.verbose_info(messages("inserting_report_db"))
    connection, cursor = create_connection()
    
    try:
        cursor.execute("BEGIN")
        cursor.execute(
            """
            INSERT INTO reports (date, scan_unique_id, report_path_filename, options)
            VALUES (?, ?, ?, ?)
            """,
            (
                str(event["date"]),
                event["scan_id"],
                event["options"]["report_path_filename"],
                json.dumps(event["options"]),
                ),
            )
        return send_submit_query(cursor)
    except Exception as e:
        cursor.execute("ROLLBACK")
        print(f"Error happened here: {e}")
        return False
    finally:
        cursor.close()


def remove_old_logs(options):
    """
    this function remove old events (and duplicated)
    from nettacker.database based on target, module, scan_id

    Args:
        options: identifiers

    Returns:
        True if success otherwise False
    """
    connection, cursor = create_connection()
    
    try:
        cursor.execute("BEGIN")
        cursor.execute(
            """
            DELETE FROM scan_events
                WHERE target = ?
                  AND module_name = ?
                  AND scan_unique_id != ?
                  AND scan_unique_id != ?
            """,
            (
                options["target"],
                options["module_name"],
                options["scan_id"],
                options["scan_compare_id"],
                ),
            )
        return send_submit_query(cursor)
    except Exception as e:
        cursor.execute("ROLLBACK")
        print(f"Error in remove_old_logs: {e}")
        return False
    finally:
        cursor.close()


def submit_logs_to_db(log):
    """
    this function created to submit new events into database

    Args:
        log: log event in JSON type

    Returns:
        True if success otherwise False
    """
    if isinstance(log, dict):
        connection, cursor = create_connection()
        try:
            cursor.execute("BEGIN")
            cursor.execute(
                """
                INSERT INTO scan_events (target, date, module_name, scan_unique_id, port, event, json_event)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log["target"],
                    str(log["date"]),
                    log["module_name"],
                    log["scan_id"],
                    json.dumps(log["port"]),
                    json.dumps(log["event"]),
                    json.dumps(log["json_event"]),
                ),
            )
            return send_submit_query(cursor)
        except Exception as e:
            cursor.execute("ROLLBACK")
            print(f"There is an issue in submit_logs_to_db: {e}")
            return False
        finally:
            cursor.close()
    else:
        log.warn(messages("invalid_json_type_to_db").format(log))
        return False


def submit_temp_logs_to_db(log):
    """
    this function created to submit new events into database

    Args:
        log: log event in JSON type

    Returns:
        True if success otherwise False
    """
    if isinstance(log, dict):
        connection, cursor = create_connection()
        
        try:
            cursor.execute("BEGIN")
            cursor.execute(
                """
                INSERT INTO temp_events (target, date, module_name, scan_unique_id, event_name, port, event, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log["target"],
                    str(log["date"]),
                    log["module_name"],
                    log["event_name"],
                    json.dumps(log["port"]),
                    json.dumps(log["event"]),
                    json.dumps(log["data"]),
                    ),
                )
            return send_submit_query(cursor)
        except Exception as e:
            cursor.execute("ROLLBACK")
            print(f"Something is wrong in submit_temp_logs_to_db: {e}")
            return False
        finally:
            cursor.close()
    else:
        log.warn(messages("invalid_json_type_to_db").format(log))
        return False


def find_temp_events(target, module_name, scan_id, event_name):
    """
    select all events by scan_unique id, target, module_name

    Args:
        target: target
        module_name: module name
        scan_id: unique scan identifier
        event_name: event_name

    Returns:
        a JSON event row or None
    """
    connection, cursor = create_connection()
    try:
        for _ in range(100):
            try:
                cursor.execute("""
                    SELECT json_event
                    FROM temp_events
                    WHERE target = ? AND module_name = ? AND scan_unique_id = ? AND event_name = ?
                    LIMIT 1
                """, (target, module_name, scan_id, event_name))
                
                row = cursor.fetchone()
                cursor.close()
                if row:
                    # Assuming json_event column stores JSON text
                    return json.loads(row[0])
                return None
            except Exception as e:
                time.sleep(0.1)
    except Exception:
        log.warn(messages("database_connect_fail"))
        return None
    return None


def find_events(target, module_name, scan_id):
    """
    select all events by scan_unique id, target, module_name

    Args:
        target: target
        module_name: module name
        scan_id: unique scan identifier

    Returns:
        an array with JSON events or an empty array
    """
    connection, cursor = create_connection()

    try:
        cursor.execute(
            """
            SELECT json_event FROM scan_events
            WHERE target = ? AND module_name = ? and scan_unique_id = ?
            """,
            (
            target, module_name, scan_id
            ),
        )

        rows = cursor.fetchall()
        cursor.close()
        if rows:
            return [json.dumps((json.loads(row[0]))) for row in rows]
        return []
    except Exception as e:
        print(f"Something went wrong in find_events: {e}")
        return []

def select_reports(page):
    """
    this function created to crawl into submitted results,
    it shows last 10 results submitted in the database.
    you may change the page (default 1) to go to next/previous page.

    Args:
        page: page number

    Returns:
        list of events in array and JSON type, otherwise an error in JSON type.
    """
    selected = []
    connection, cursor = create_connection()
    offset = (page-1) * 10

    try:
        cursor.execute(
            """
            SELECT id, date, scan_unique_id, report_path_filename, options
            FROM reports
            ORDER BY id DESC
            LIMIT 10 OFFSET ?
            """,
            (offset,),
        )

        rows = cursor.fetchall()

        cursor.close()
        for row in rows:
            tmp = {
                "id": row[0],
                "date": str(row[1]),
                "scan_id": row[2],
                "report_path_filename": row[3],
                "options": json.loads(row[4]),
            }
            selected.append(tmp)
        return selected

    except Exception as e:
        print(f"Database error in select_reports: {e}")
        return structure(status="error", msg="database error!")


def get_scan_result(id):
    """
    this function created to download results by the result ID.

    Args:
        id: scan id

    Returns:
        result file content (TEXT, HTML, JSON) if success otherwise and error in JSON type.
    """
    connection, cursor = create_connection()
    cursor.execute(
        """
        SELECT report_path_filename from reports
        WHERE id = ?
        """, (id),
        )

    row = cursor.fetchone()
    cursor.close()
    if row:
        filename = row[0]
        return filename, open(str(filename), "rb").read()
    else:
        return structure(status="error", msg="database error!")


def last_host_logs(page):
    """
    this function created to select the last 10 events from the database.
    you can goto next page by changing page value.

    Args:
        page: page number

    Returns:
        an array of events in JSON type if success otherwise an error in JSON type
    """
    connection, cursor = create_connection()
    
    try:
        cursor.execute(
            """
            SELECT DISTINCT target 
            FROM scan_events
            ORDER BY id DESC 
            LIMIT 10 OFFSET ?
            """, 
            [(page - 1) * 10]
        )
        targets = cursor.fetchall()
        
        if not targets:
            return structure(status="finished", msg="No more search results")
        
        hosts = []
        
        for (target,) in targets:
            cursor.execute(
                """
                SELECT DISTINCT module_name 
                FROM scan_events
                WHERE target = ?
                """,
                [target]
            )
            module_names = [row[0] for row in cursor.fetchall()]
            
            cursor.execute(
                """
                SELECT date 
                FROM scan_events
                WHERE target = ? 
                ORDER BY id DESC 
                LIMIT 1
                """,
                [target]
            )
            latest_date = cursor.fetchone()
            latest_date = latest_date[0] if latest_date else None
            
            cursor.execute(
                """
                SELECT event 
                FROM scan_events
                WHERE target = ?
                """,
                [target]
            )
            events = [row[0] for row in cursor.fetchall()]
            
            cursor.close()
            hosts.append(
                {
                    "target": target,
                    "info": {
                        "module_name": module_names,
                        "date": latest_date,
                        "events": events,
                    },
                }
            )

        return hosts

    except Exception as e:
        log.warn(f"Database query failed: {e}")
        return structure(status="error", msg="Database error!")


def get_logs_by_scan_id(scan_id):
    """
    select all events by scan id hash

    Args:
        scan_id: scan id hash

    Returns:
        an array with JSON events or an empty array
    """
    connection, cursor = create_connection()
    
    cursor.execute(
        """
        SELECT scan_unique_id, target, module_name, date, port, event, json_event
        from scan_events
        WHERE scan_unique_id = ?
        """, (scan_id,)                 # We have to put this as a indexed element
        )
    rows = cursor.fetchall()

    cursor.close()
    return [
        {
            "scan_id": row[0],
            "target": row[1],
            "module_name": row[2],
            "date": str(row[3]),
            "port": json.loads(row[4]),
            "event": json.loads(row[5]),
            "json_event": json.loads(row[6]) if row[6] else {}
        }
        for row in rows
    ]


def get_options_by_scan_id(scan_id):
    """
    select all stored options of the scan by scan id hash
    Args:
        scan_id: scan id hash
    Returns:
        an array with a dict with stored options or an empty array
    """
    connection, cursor = create_connection()
    
    cursor.execute(
        """
        SELECT options from reports
        WHERE scan_unique_id = ?
        """,
        (scan_id,)
        )
    rows = cursor.fetchall()
    cursor.close()
    if rows:
        return [{"options": row[0]} for row in rows]


def logs_to_report_json(target):
    """
    select all reports of a host

    Args:
        host: the host to search

    Returns:
        an array with JSON events or an empty array
    """
    try:
        connection, cursor = create_connection()
        return_logs = []

        cursor.execute(
            """
            SELECT scan_unique_id, target, port, event, json_event
            FROM scan_events WHERE target = ?
            """,
            (target,)
            )
        rows = cursor.fetchall()
        cursor.close()
        if rows:
            for log in rows:
                data = {
                "scan_id": log[0],
                "target": log[1],
                "port": json.loads(log[2]),
                "event": json.loads(log[3]),
                "json_event": json.loads(log[4]),
                }
            return_logs.append(data)

            return return_logs
    except Exception:
        return []


def logs_to_report_html(target):
    """
    generate HTML report with d3_tree_v2_graph for a host

    Args:
        target: the target

    Returns:
        HTML report
    """
    from nettacker.core.graph import build_graph
    from nettacker.lib.html_log import log_data

    connection, cursor = create_connection()
    cursor.execute(
        """
        SELECT date, target, module_name, scan_unique_id, port, event, json_event
        FROM scan_events
        WHERE target = ?
        """,
        (target,)
    )

    rows = cursor.fetchall()
    cursor.close()
    logs = [
        str({
            "date": log[0],
            "target": log[1],
            "module_name": log[2],
            "scan_id": log[3],
            "port": log[4],
            "event": log[5],
            "json_event": log[6],
        })

        for log in rows
    ]


    html_graph = build_graph("d3_tree_v2_graph", logs)

    html_content = log_data.table_title.format(
        html_graph,
        log_data.css_1,
        "date",
        "target",
        "module_name",
        "scan_id",
        "port",
        "event",
        "json_event",
    )
    for event in logs:
        html_content += log_data.table_items.format(
            event["date"],
            event["target"],
            event["module_name"],
            event["scan_id"],
            event["port"],
            event["event"],
            event["json_event"],
        )
    html_content += (
        log_data.table_end + '<p class="footer">' + messages("nettacker_report") + "</p>"
    )
    return html_content


def search_logs(page, query):
    """
    search in events (host, date, port, module, category, description,
    username, password, scan_id, scan_cmd)

    Args:
        page: page number
        query: query to search

    Returns:
        an array with JSON structure of found events or an empty array
    """
    connection, cursor = create_connection()
    selected = []
    try:
        # Fetch targets matching the query
        cursor.execute(
            """
            SELECT DISTINCT target FROM scan_events
            WHERE target LIKE ? OR date LIKE ? OR module_name LIKE ?
            OR port LIKE ? OR event LIKE ? OR scan_unique_id LIKE ?
            ORDER BY id DESC
            LIMIT 10 OFFSET ?
            """,
            (
                f"%{query}%", f"%{query}%", f"%{query}%",
                f"%{query}%", f"%{query}%", f"%{query}%",
                (page * 10) - 10,
            )
        )
        targets = cursor.fetchall()
        cursor.close()
        for target_row in targets:
            target = target_row[0]
            # Fetch data for each target grouped by key fields
            cursor.execute(
                """
                SELECT date, module_name, port, event, json_event FROM scan_events
                WHERE target = ?
                GROUP BY module_name, port, scan_unique_id, event
                ORDER BY id DESC
                """,
                (target,)
            )
            results = cursor.fetchall()

            tmp = {
                "target": target,
                "info": {
                    "module_name": [],
                    "port": [],
                    "date": [],
                    "event": [],
                    "json_event": [],
                },
            }

            for data in results:
                date, module_name, port, event, json_event = data
                if module_name not in tmp["info"]["module_name"]:
                    tmp["info"]["module_name"].append(module_name)
                if date not in tmp["info"]["date"]:
                    tmp["info"]["date"].append(date)
                parsed_port = json.loads(port)
                if parsed_port not in tmp["info"]["port"]:
                    tmp["info"]["port"].append(parsed_port)
                parsed_event = json.loads(event)
                if parsed_event not in tmp["info"]["event"]:
                    tmp["info"]["event"].append(parsed_event)
                parsed_json_event = json.loads(json_event)
                if parsed_json_event not in tmp["info"]["json_event"]:
                    tmp["info"]["json_event"].append(parsed_json_event)

            selected.append(tmp)

    except Exception as e:
        return structure(status="error", msg=f"database error! {e}")

    if len(selected) == 0:
        return structure(status="finished", msg="No more search results")
    return selected