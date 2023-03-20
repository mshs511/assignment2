import cx_Oracle
import streamlit as st
import time
import sqlparse
from sqlparse.sql import IdentifierList, Identifier
from sqlparse.tokens import Keyword, DML, Newline, Whitespace
import re
import pandas as pd

# Define help page function
def help_page():
    st.title("Oracle DataBeast Performance Optimizer")
    st.subheader("Introduction")
    st.write("""
    This app provides an interface for analyzing and optimizing the performance of an Oracle Database.
    Select a page from the sidebar menu to access the various functionalities.
    """)

    st.subheader("Functionalities")

    st.write("### Manage Tables")
    st.write("""
    - View existing tables and their details.
    - Create new tables or modify existing tables with specified columns and data types.
    - Import data from external files (CSV, Excel) into tables.
    """)

    st.write("### Diagnosis and Report Generation")
    st.write("""
    - Evaluate performance metrics such as top SQL queries by elapsed time, top sessions by wait time, and cache hit ratios.
    - Identify resource-intensive queries and sessions for further analysis and optimization.
    """)

    st.write("### Tablespace and Partition Management")
    st.write("""
    - Monitor and manage tablespace usage, including data file sizes and free space.
    - Analyze SQL queries to suggest partitioning strategies and apply them to your tables.
    - Create, modify, and drop partitions to optimize table storage and query performance.
    """)

    st.write("### Indexing")
    st.write("""
    - Create, modify, and drop indexes to improve query performance.
    - Monitor index usage and identify indexes that can be optimized or dropped.
    """)

    st.write("### Query Optimization")
    st.write("""
    - Analyze and optimize SQL queries for better performance.
    - Identify inefficient queries and suggest improvements, such as rewriting, adding indexes, or partitioning.
    """)

    st.write("### User Management")
    st.write("""
    - Create, modify, and drop database users and their privileges.
    - Monitor user activity and resource usage.
    - Manage user roles and permissions.
    """)

def get_user_tables(connection):
    current_user = st.session_state.username
    is_dba = is_user_dba(connection)

    cursor = connection.cursor()
    if is_dba:
        query = f"""
            SELECT owner, table_name
            FROM all_tables
            WHERE owner NOT IN ('SYS', 'ORDDATA', 'DBSFWUSER', 'SYSTEM', 'OUTLN', 'MDSYS', 'CTXSYS', 'DVSYS', 'DBSNMP', 'ORDSYS', 'ORDPLUGINS', 'SI_INFORMTN_SCHEMA', 'OLAPSYS', 'WMSYS', 'ANONYMOUS', 'XDB', 'APEX_PUBLIC_USER', 'APPQOSSYS', 'DIP', 'EXFSYS', 'GSMADMIN_INTERNAL', 'LBACSYS', 'MDDATA', 'ORACLE_OCM', 'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR', 'SYSMAN', 'WK_TEST', 'WKSYS', 'WKPROXY', 'WMSYS', 'XS$NULL', 'OJVMSYS', 'AUDSYS', 'GSMADMIN_INTERNAL', 'DVF', 'DVSYS')
            AND table_name NOT LIKE 'SYS_%'
            AND table_name NOT LIKE 'APEX_%'
            ORDER BY owner, table_name
        """
    else:
        query = f"""
            SELECT table_name
            FROM user_tables
            ORDER BY table_name
        """
    cursor.execute(query)
    return cursor.fetchall()

def manage_tables(connection):
    st.subheader("Manage Tables")

    # Display tables
    st.subheader("Existing Tables")
    tables = get_user_tables(connection)
    st.write("Tables:")
    st.write(pd.DataFrame(tables, columns=["Creator", "Table Name"]))

    is_dba = is_user_dba(connection)

    if is_dba:
        st.error("It is bad practice to create tables as SYSTEM or DBA. Please log in as a different user to create tables.")
    else:
        # Create a new table
        st.subheader("Create a New Table")
        table_name = st.text_input("Enter table name:")
        schema_input = st.text_area("Enter the schema in the format 'column_name datatype, column_name datatype, ...':")
        create_button = st.button("Create Table")

        if create_button:
            if table_name and schema_input:
                # Use the provided schema to create a table
                query = f"CREATE TABLE {table_name} ({schema_input})"
                cursor = connection.cursor()
                try:
                    cursor.execute(query)
                    st.success(f"Table '{table_name}' created successfully.")
                except Exception as e:
                    st.error(f"Failed to create table '{table_name}': {e}")
                cursor.close()
            else:
                st.warning("Please enter a table name and schema to create a new table.")

    # Delete a table
    st.subheader("Delete a Table")
    selected_table = st.selectbox("Select a table to delete:", [("",) if is_dba else ""] + tables)
    delete_button = st.button("Delete Table")

    if delete_button:
        if selected_table:
            query = f"DROP TABLE {selected_table}"
            cursor = connection.cursor()
            try:
                cursor.execute(query)
                st.success(f"Table '{selected_table}' deleted successfully.")
            except Exception as e:
                st.error(f"Failed to delete table '{selected_table}': {e}")
            cursor.close()
        else:
            st.warning("Please select a table to delete.")

def query_optimization():
    st.subheader("Query Optimization")

    input_query = st.text_area("Enter your SQL query:")
    optimize_button = st.button("Optimize Query")

    if optimize_button:
        if input_query:
            optimized_query, rationales = optimize_query(input_query)
            st.write("Original Query:")
            st.code(input_query, language="sql")

            st.write("Optimized Query:")
            st.code(optimized_query, language="sql")

            st.write("Rationale:")
            for rationale in rationales:
                st.write("- " + rationale)
        else:
            st.warning("Please enter a SQL query to optimize.")

def optimize_query(query):
    parsed_query = sqlparse.parse(query)[0]
    rationales = []

    # Remove unnecessary DISTINCT clauses
    for token in parsed_query.tokens:
        if token.ttype is Keyword and token.value.upper() == "DISTINCT":
            parsed_query.tokens.remove(token)
            rationales.append("Removed unnecessary DISTINCT clause")

    # Simplify JOIN conditions
    for idx, token in enumerate(parsed_query.tokens):
        if token.ttype is Keyword and token.value.upper() == "INNER JOIN":
            parsed_query.tokens[idx].value = "JOIN"
            rationales.append("Simplified INNER JOIN to JOIN")

    # Replace SELECT * with a specific list of columns, if needed
    # You can replace ['column1', 'column2'] with the actual column names you want to select
    for idx, token in enumerate(parsed_query.tokens):
        if token.ttype is DML and token.value.upper() == "SELECT":
            next_token = parsed_query.token_next(idx)
            if next_token[1] == "*":
                parsed_query.tokens.remove(next_token)
                parsed_query.tokens.insert(idx + 1, IdentifierList([Identifier('column1'), Identifier('column2')]))
                rationales.append("Replaced SELECT * with specific column names")

    return sqlparse.format(str(parsed_query), reindent=True, keyword_case='upper'), rationales

# Define the function for connecting to the Oracle database
def create_connection(username, password, hostname, port, sid):
    dsn_tns = cx_Oracle.makedsn(hostname, port, sid)
    connection = cx_Oracle.connect(username, password, dsn_tns)
    return connection

def get_current_user(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT user FROM dual")
    result = cursor.fetchone()
    cursor.close()
    return result[0]

# Define a function for the Diagnosis and Report Generation page

def diagnosis_report(connection):
    username = get_current_user(connection)
    if username.upper() not in ['SYSTEM', 'SYS']:
        st.warning("You must be logged in as SYSTEM or SYS to use this functionality.")
        return

    st.subheader("Top 10 SQL Queries by Elapsed Time")
    top_sql_elapsed_time = get_top_sql_elapsed_time(connection)
    st.write(pd.DataFrame(top_sql_elapsed_time, columns=['SQL_ID', 'Elapsed Time per Execution', 'Executions', 'SQL Text']))

    st.subheader("Top 10 SQL Queries by CPU Time")
    top_sql_cpu_time = get_top_sql_cpu_time(connection)
    st.write(pd.DataFrame(top_sql_cpu_time, columns=['SQL_ID', 'CPU Time per Execution', 'Executions', 'SQL Text']))

    st.subheader("Top 10 Sessions by Wait Time")
    top_sessions_wait_time = get_top_sessions_wait_time(connection)
    st.write(pd.DataFrame(top_sessions_wait_time, columns=['SID', 'Serial#', 'Username', 'Status', 'Event', 'Wait Class', 'Wait Time', 'Seconds in Wait']))

    st.subheader("Top 10 Segments by Physical Reads")
    top_segments_physical_reads = get_top_segments_physical_reads(connection)
    st.write(pd.DataFrame(top_segments_physical_reads, columns=['Owner', 'Object Name', 'Subobject Name', 'Object Type', 'Value']))
    
    st.subheader("Database Buffer Cache Hit Ratio")
    buffer_cache_hit_ratio = get_buffer_cache_hit_ratio(connection)
    st.write(f"{buffer_cache_hit_ratio[0]:.2f}%")
    
    st.subheader("Library Cache Hit Ratio")
    library_cache_hit_ratio = get_library_cache_hit_ratio(connection)
    st.write(f"{library_cache_hit_ratio[0]:.2f}%")

    st.subheader("Disk Space Usage")
    disk_space_usage = get_disk_space_usage(connection)
    st.write(pd.DataFrame(disk_space_usage, columns=['Tablespace Name', 'Used Space (MB)', 'Total Space (MB)', 'Percentage Used']))

    st.subheader("Active Sessions")
    active_sessions = get_active_sessions(connection)
    st.write(f"Active Sessions: {active_sessions[0]}")

    st.subheader("Long Running Queries (Longer than 60 seconds)")
    long_running_queries = get_long_running_queries(connection)
    st.write(pd.DataFrame(long_running_queries, columns=['SID', 'Serial#', 'Username', 'Status', 'Program', 'SQL Text']))


def get_disk_space_usage(connection):
    query = """
        SELECT tablespace_name, used_space, tablespace_size, ROUND((used_space / tablespace_size) * 100, 2) as pct_used
        FROM (
            SELECT a.tablespace_name,
                   a.bytes_alloc / (1024 * 1024) as tablespace_size,
                   nvl(b.bytes_used, 0) / (1024 * 1024) as used_space
            FROM (SELECT tablespace_name, SUM(bytes) bytes_alloc
                  FROM sys.sm$ts_avail
                  GROUP BY tablespace_name) a,
                 (SELECT tablespace_name, SUM(bytes) bytes_used
                  FROM dba_segments
                  GROUP BY tablespace_name) b
            WHERE a.tablespace_name = b.tablespace_name(+)
        )
    """
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()

def get_active_sessions(connection):
    query = """
        SELECT COUNT(*) FROM v$session WHERE status = 'ACTIVE'
    """
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchone()

def get_long_running_queries(connection, threshold_seconds=60):
    query = f"""
        SELECT s.sid, s.serial#, s.username, s.status, s.program, q.sql_text
        FROM v$session s
        JOIN v$sql q ON s.sql_id = q.sql_id
        WHERE s.status = 'ACTIVE' AND s.sql_exec_start < (SYSTIMESTAMP - INTERVAL '{threshold_seconds}' SECOND)
    """
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()

def get_library_cache_hit_ratio(connection):
    query = """
        SELECT SUM(PINS - RELOADS) / SUM(PINS) * 100 AS library_cache_hit_ratio
        FROM V$LIBRARYCACHE
    """
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def get_buffer_cache_hit_ratio(connection):
    query = """
        SELECT (1 - (phy.value / (cur.value + con.value))) * 100 AS cache_hit_ratio
        FROM V$SYSSTAT cur, V$SYSSTAT con, V$SYSSTAT phy
        WHERE cur.name = 'db block gets'
        AND con.name = 'consistent gets'
        AND phy.name = 'physical reads'
    """
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def get_top_segments_physical_reads(connection):
    query = """
        SELECT owner, object_name, subobject_name, object_type, value
        FROM V$SEGMENT_STATISTICS
        WHERE statistic_name = 'physical reads' AND ROWNUM <= 10
        ORDER BY value DESC
    """
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def get_top_sessions_wait_time(connection):
    query = """
        SELECT sid, serial#, username, status, event, wait_class, wait_time, seconds_in_wait
        FROM V$SESSION
        WHERE ROWNUM <= 10
        ORDER BY wait_time DESC
    """
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()

def get_top_sql_cpu_time(connection):
    query = """
        SELECT sql_id,
            ROUND(cpu_time / NULLIF(executions, 0), 2) as cpu_time_per_execution,
            executions,
            sql_text
        FROM V$SQL
        WHERE ROWNUM <= 10
        ORDER BY cpu_time DESC
    """
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def get_top_sql_elapsed_time(connection):
    query = """
        SELECT sql_id,
            ROUND(elapsed_time / NULLIF(executions, 0), 2) as elapsed_time_per_execution,
            executions,
            sql_text
        FROM V$SQL
        WHERE ROWNUM <= 10
        ORDER BY elapsed_time DESC
    """
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Define a function for the Indexing page
def get_tables(connection):
    query = """SELECT table_name 
               FROM all_tables 
               WHERE owner = :owner AND owner NOT IN ('SYS', 'SYSTEM')"""
    cursor = connection.cursor()
    cursor.execute(query, owner=st.session_state.username.upper())
    return [row[0] for row in cursor.fetchall()]

def analyze_table(connection, table_name):
    cursor = connection.cursor()
    query = f"ANALYZE TABLE {table_name} COMPUTE STATISTICS"
    cursor.execute(query)
    connection.commit()

def get_column_statistics(connection, table_name):
    query = """SELECT column_name, num_distinct, num_nulls, density
               FROM all_tab_col_statistics
               WHERE table_name = :table_name AND owner = :owner"""
    cursor = connection.cursor()
    cursor.execute(query, table_name=table_name, owner=st.session_state.username.upper())
    return cursor.fetchall()

def should_create_index(column_stats):
    column_name, num_distinct, num_nulls, density = column_stats
    selectivity = num_distinct / (num_distinct + num_nulls)
    # Customize this threshold according to your requirements
    selectivity_threshold = 0.7
    st.write("The selectivity of ", column_name, "is - ", selectivity)
    
    if selectivity >= selectivity_threshold:
        return True
    return False

def create_index(connection, table_name, column_name):
    index_name = f"{table_name}_{column_name}_IDX"
    query = f"CREATE INDEX {index_name} ON {table_name}({column_name})"
    cursor = connection.cursor()
    cursor.execute(query)
    connection.commit()

def get_used_columns(query):
    column_regex = re.compile(r"SELECT\s+(.*?)\s+FROM", re.IGNORECASE)
    match = column_regex.search(query)
    if match:
        columns = match.group(1).split(',')
        return [col.strip() for col in columns]
    return []

def indexing(connection):
    st.subheader("Indexing")

    # Get tables
    tables = get_tables(connection)
    st.subheader("Tables belonging to current user")
    st.write(tables)

    # Input query
    st.subheader("Enter Query")
    query_input = st.text_area("Enter your query:")
    run_query_button = st.button("Run Query")

    query_based_suggested_indexes = []
    if run_query_button:
        if query_input:
            # Run the query
            try:
                cursor = connection.cursor()
                cursor.execute(query_input.strip())  # Strip the query to remove any leading/trailing whitespaces
                st.success("Query executed successfully.")
                results = cursor.fetchall()
                st.write("Query results:")
                st.write(results)
            except Exception as e:
                st.error(f"Error running the query: {e}")
            cursor.close()

            # Get columns used in the query
            used_columns = get_used_columns(query_input)
            if used_columns:
                st.write("Columns used in the query:")
                st.write(used_columns)

            # Analyze table and get column statistics
            for table in tables:
                # Analyze table
                try:
                    analyze_table(connection, table)
                except Exception as e:
                    st.error(f"Error analyzing table {table}: {e}")

                # Get column statistics
                try:
                    column_stats = get_column_statistics(connection, table)
                except Exception as e:
                    st.error(f"Error getting column statistics for table {table}: {e}")
                    continue

                # Determine if an index should be created
                for stats in column_stats:
                    if stats[0].lower() in used_columns:
                        if should_create_index(stats):
                            query_based_suggested_indexes.append((table, stats[0]))

            if query_based_suggested_indexes !=[]:
                st.write("Query-based suggested indexes:")
                for index in query_based_suggested_indexes:
                    st.write(f"Table: {index[0]}, Column: {index[1]}")
            else:
                st.write("Your query is already running efficiently! It does not require further indexing.")

    # Table analysis-based indexing suggestions
    st.subheader("Table Analysis-based Indexing Suggestions")

    table_analysis_suggested_indexes = []
    for table in tables:
        # Analyze table
        try:
            analyze_table(connection, table)
        except Exception as e:
            st.error(f"Error analyzing table {table}: {e}")

        # Get column statistics
        try:
            column_stats = get_column_statistics(connection, table)
        except Exception as e:
            st.error(f"Error getting column statistics for table {table}: {e}")
            continue

        # Determine if an index should be created
        for stats in column_stats:
            if should_create_index(stats):
                table_analysis_suggested_indexes.append((table, stats[0]))

    if table_analysis_suggested_indexes:
        st.write("Table analysis-based suggested indexes:")
        for index in table_analysis_suggested_indexes:
            st.write(f"Table: {index[0]}, Column: {index[1]}")

        # Create indexes if the user confirms
        if st.button("Create suggested indexes"):
            all_suggested_indexes = query_based_suggested_indexes + table_analysis_suggested_indexes
            for index in all_suggested_indexes:
                try:
                    create_index(connection, index[0], index[1])
                    st.success(f"Index created for Table: {index[0]}, Column: {index[1]}")
                except Exception as e:
                    st.error(f"Error creating index for Table: {index[0]}, Column: {index[1]}: {e}")
    else:
        st.write("No suggested indexes found.")


# Define a function for the Tablespace and Partition Management page
def is_user_dba(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT GRANTED_ROLE FROM USER_ROLE_PRIVS WHERE GRANTED_ROLE = 'DBA'")
    result = cursor.fetchone()
    cursor.close()
    return result is not None

def get_tablespaces(connection):
    username = get_current_user(connection)
    if username.upper() in ['SYSTEM', 'SYS']:
        query = """
            SELECT tablespace_name, SUM(bytes) AS bytes, SUM(maxbytes) AS maxbytes
            FROM dba_data_files
            GROUP BY tablespace_name
        """
    else:
        query = """
            SELECT tablespace_name, bytes, max_bytes
            FROM user_ts_quotas
        """
    cursor = connection.cursor()
    cursor.execute(query)
    tablespaces = cursor.fetchall()
    cursor.close()
    return tablespaces



def create_tablespace(connection):
    st.subheader("Create Tablespace")
    tablespace_name = st.text_input("Enter tablespace name:")
    size_mb = st.number_input("Enter initial size in MB:", min_value=1, value=10)
    create_button = st.button("Create Tablespace")

    if create_button:
        if tablespace_name:
            query = f"""
                CREATE TABLESPACE {tablespace_name}
                DATAFILE '{tablespace_name}.dbf'
                SIZE {size_mb}M
                AUTOEXTEND ON
            """
            cursor = connection.cursor()
            try:
                cursor.execute(query)
                st.success(f"Tablespace '{tablespace_name}' created successfully.")
                reload = st.button("Reload")

                if reload:
                    st.experimental_rerun()
            except Exception as e:
                st.error(f"Failed to create tablespace '{tablespace_name}': {e}")
            cursor.close()
        else:
            st.warning("Please enter a tablespace name to create a new tablespace.")

def analyze_query_for_partitions(query):
    range_regex = r"(\w+)\s+(>|<)\s+('?\d{4}-\d{2}-\d{2}'?|\d+)"
    aggregate_regex = r"(COUNT|SUM|AVG|MIN|MAX)\s*\(\s*(\w+)\s*\)"

    range_match = re.search(range_regex, query)
    aggregate_match = re.search(aggregate_regex, query)

    suggestions = []

    if range_match:
        attribute_name = range_match.group(1)
        suggestions.append(('RANGE', attribute_name))
    
    if aggregate_match:
        attribute_name = aggregate_match.group(2)
        suggestions.append(('LIST', attribute_name))

    return suggestions

#could not debug
# def apply_partition(connection, table_name, partition_type, attribute_name):
#     cursor = connection.cursor()
    
#     # Check if the table is already partitioned
#     cursor.execute(f"SELECT partitioning_type FROM user_tables WHERE table_name = '{table_name}'")
#     current_partitioning_type = cursor.fetchone()[0]
#     if current_partitioning_type:
#         st.error(f"The table '{table_name}' is already partitioned with '{current_partitioning_type}' partitioning.")
#         return

#     if partition_type == 'RANGE':
#         # Get minimum and maximum values of the attribute
#         cursor.execute(f"SELECT MIN({attribute_name}), MAX({attribute_name}) FROM {table_name}")
#         min_value, max_value = cursor.fetchone()

#         # Calculate partition ranges
#         partition_count = 3
#         range_step = (max_value - min_value) // partition_count
#         partition_ranges = [min_value + range_step * i for i in range(partition_count)]

#         # Create range partitions
#         partition_query = f"ALTER TABLE {table_name} PARTITION BY RANGE({attribute_name}) ("
#         for i, partition_range in enumerate(partition_ranges):
#             partition_query += f"PARTITION p{i} VALUES LESS THAN ({partition_range}), "
#         partition_query += "PARTITION pMAX VALUES LESS THAN (MAXVALUE))"

#         cursor.execute(partition_query)

#     elif partition_type == 'LIST':
#         # Get distinct values of the attribute
#         cursor.execute(f"SELECT DISTINCT({attribute_name}) FROM {table_name}")
#         distinct_values = [row[0] for row in cursor.fetchall()]

#         # Create list partitions
#         partition_query = f"ALTER TABLE {table_name} PARTITION BY LIST({attribute_name}) ("
#         for i, value in enumerate(distinct_values):
#             partition_query += f"PARTITION p{i} VALUES ('{value}'), "
#         partition_query = partition_query.rstrip(", ") + ")"

#         cursor.execute(partition_query)

#     connection.commit()
#     st.success(f"Applied {partition_type} partition on attribute '{attribute_name}' for table '{table_name}'.")

def manage_partitions(connection):
    # Read user input
    query = st.text_area("Enter a query:")
    execute_button = st.button("Execute Query")

    if execute_button:
        if query:
            # Analyze the query for partitioning suggestions
            partition_suggestions = analyze_query_for_partitions(query)
            if partition_suggestions:
                st.write("Partitioning suggestions:")
                for partition_type, attribute_name in partition_suggestions:
                    st.write(f"Apply {partition_type} partition on attribute '{attribute_name}'.")
            else:
                st.write("No partitioning suggestions found.")

            # Create a cursor from the connection to run the query
            with connection.cursor() as cursor:
                try:
                    cursor.execute(query)
                    result = cursor.fetchall()
                    st.write("Query result:")
                    st.write(result)
                except Exception as e:
                    st.error(f"An error occurred while executing the query: {e}")
        else:
            st.warning("Please enter a query to execute and analyze for partitioning suggestions.")


def drop_tablespace(connection, tablespaces):
    st.subheader("Drop Tablespace")
    selected_tablespace = st.selectbox("Select a tablespace to delete:", [("",)] + tablespaces)
    drop_button = st.button("Drop Tablespace")

    if drop_button:
        if selected_tablespace:
            query = f"DROP TABLESPACE {selected_tablespace} INCLUDING CONTENTS AND DATAFILES"
            cursor = connection.cursor()
            try:
                cursor.execute(query)
                st.success(f"Tablespace '{selected_tablespace}' deleted successfully.")
                reload = st.button("Reload")

                if reload:
                    st.experimental_rerun()
            except Exception as e:
                st.error(f"Failed to delete tablespace '{selected_tablespace}': {e}")
            cursor.close()
        else:
            st.warning("Please select a tablespace to delete.")


def tablespace_partition(connection):
    st.subheader("Tablespaces")
    # Display tablespaces
    tablespaces = get_tablespaces(connection)
    st.write("Current Tablespaces:")
    st.write(pd.DataFrame(tablespaces, columns=['Name', 'Used Storage', 'Total Storage Available']))

    # Create and delete tablespaces
    create_tablespace(connection)
    drop_tablespace(connection, [ts[0] for ts in tablespaces])

    # Display partitioned tables
    st.subheader("Partitioned Tables")
    partitioned_tables = get_partitioned_tables(connection, st.session_state.username)
    st.write("Current Partitioned Tables:")
    st.write(pd.DataFrame(partitioned_tables, columns=['Table', 'Partition Name']))

    # Analyze queries for partitioning suggestions
    st.subheader("Analyze Queries for Partitioning Suggestions")
    manage_partitions(connection)

# Function to fetch partitioned tables

def get_partitioned_tables(connection, current_user):
    cursor = connection.cursor()
    query = f"""
        SELECT table_name, partition_name
        FROM all_tab_partitions
        WHERE table_owner = '{current_user}'
        ORDER BY table_name, partition_name
    """
    cursor.execute(query)
    return cursor.fetchall()



# Define a function for the User Management page
def get_users_and_roles(connection):
    # Check if the user has access to DBA_USERS view
    has_dba_users_access = check_dba_users_access(connection)
    
    # Use DBA_USERS view if the user has access, otherwise use ALL_USERS
    view_name = "DBA_USERS" if has_dba_users_access else "ALL_USERS"

    query = f"""
    SELECT USERNAME
    FROM {view_name}
    WHERE USERNAME LIKE 'C##%'
    ORDER BY USERNAME
    """

    cursor = connection.cursor()
    cursor.execute(query)
    result = cursor.fetchall()
    cursor.close()

    users = [row[0] for row in result]

    return users


def check_dba_users_access(connection):
    query = """
    SELECT COUNT(*)
    FROM ALL_TAB_PRIVS
    WHERE TABLE_NAME = 'DBA_USERS' AND PRIVILEGE = 'SELECT'
    """

    cursor = connection.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    cursor.close()

    return result[0] > 0

def create_user(connection, username, password):
    if not username.startswith("C##"):
        raise ValueError("Usernames must start with 'C##'.")
    
    cursor = connection.cursor()
    
    # Create user
    query = f"""CREATE USER {username} IDENTIFIED BY "{password}"
                DEFAULT TABLESPACE users
                TEMPORARY TABLESPACE temp"""
    cursor.execute(query)
    connection.commit()
    
    # Grant necessary privileges
    grant_query = f"GRANT CONNECT, RESOURCE, CREATE VIEW TO {username}"
    cursor.execute(grant_query)
    
    connection.commit()

def modify_user_password(connection, username, new_password):
    if not username.startswith("C##"):
        raise ValueError("Usernames must start with 'C##'.")
    cursor = connection.cursor()
    query = f"ALTER USER {username} IDENTIFIED BY {new_password}"
    cursor.execute(query)
    connection.commit()

def delete_user(connection, username):
    if not username.startswith("C##"):
        raise ValueError("Usernames must start with 'C##'.")
    cursor = connection.cursor()
    query = f"DROP USER {username} CASCADE"
    cursor.execute(query)
    connection.commit()


def change_user_role(connection, username, role, action, object_name=None):
    cursor = connection.cursor()
    
    if action == "GRANT":
        if role in ["SELECT", "INSERT", "UPDATE", "DELETE", "EXECUTE"] and object_name is not None:
            query = f"GRANT {role} ON {object_name} TO {username}"
        else:
            query = f"GRANT {role} TO {username}"
    elif action == "REVOKE":
        if role in ["SELECT", "INSERT", "UPDATE", "DELETE", "EXECUTE"] and object_name is not None:
            query = f"REVOKE {role} ON {object_name} FROM {username}"
        else:
            query = f"REVOKE {role} FROM {username}"
    else:
        raise ValueError("Invalid action. Choose either 'GRANT' or 'REVOKE'.")
    
    cursor.execute(query)
    connection.commit()

def has_user_management_privileges(connection):
    required_privileges = ['CREATE USER', 'ALTER USER', 'DROP USER']

    query = """
    SELECT PRIVILEGE
    FROM USER_SYS_PRIVS
    WHERE PRIVILEGE IN (:create_user, :alter_user, :drop_user)
    """

    cursor = connection.cursor()
    cursor.execute(query, create_user=required_privileges[0], alter_user=required_privileges[1], drop_user=required_privileges[2])
    result = cursor.fetchall()
    cursor.close()

    user_privileges = [row[0] for row in result]

    # Check if the user has all required privileges
    if set(required_privileges).issubset(set(user_privileges)):
        return True
    else:
        return False

def user_management(connection):
    st.subheader("User Management")

    has_privileges = has_user_management_privileges(connection)

    # List users and their roles
    users = get_users_and_roles(connection)
    st.write("Current Users:")
    st.write(pd.DataFrame(users, columns=["Username"]))

    # Run As form
    with st.form("run_as_form"):
        st.subheader("Run As")
        run_as_username = st.text_input("Username")
        run_as_password = st.text_input("Password", type="password")
        run_as_button = st.form_submit_button("Run As")

    if run_as_button:
        try:
            run_as_connection = create_connection(run_as_username, run_as_password, st.session_state.hostname, st.session_state.port, st.session_state.sid)
            st.session_state.connection = run_as_connection
            st.session_state.username = run_as_username
            st.success(f"Connected as {run_as_username}!")

            reload = st.button("Reload Page")
            if reload:
                st.experimental_rerun()
        except Exception as e:
            st.error(f"Connection failed: {e}")

    if st.session_state.username.lower() != 'system' and not has_user_management_privileges(connection):
        st.error("Your current user does not have the necessary privileges for user management. "
                 "Please log in with a user that has CREATE USER, ALTER USER, and DROP USER privileges.")
        return
    
    # Add a form for creating a new user
    with st.form("create_user_form"):
        st.subheader("Create a New User")
        new_username = st.text_input("Username (must start with 'C##')")
        new_password = st.text_input("Password", type="password")
        create_user_button = st.form_submit_button("Create User")

    # If the Create User button is clicked, call the create_user function
    if create_user_button:
        try:
            create_user(st.session_state.connection, new_username, new_password)
            st.success(f"User {new_username} created successfully!")

            reload = st.button("Reload Page")
            if reload:
                st.experimental_rerun()
        except Exception as e:
            st.error(f"User creation failed: {e}")

    # Modify user form
    with st.form("modify_user_form"):
        st.subheader("Modify User")
        username = st.text_input("Username (must start with 'C##')")
        new_password = st.text_input("New Password", type="password")
        modify_user_button = st.form_submit_button("Modify User")

    if modify_user_button:
        try:
            modify_user_password(connection, username, new_password)
            st.success("User modified successfully!")
            reload = st.button("Reload Page")
            if reload:
                st.experimental_rerun()
        except Exception as e:
            st.error(f"User modification failed: {e}")


    # Remove user form
    with st.form("remove_user_form"):
        st.subheader("Remove User")
        del_username = st.text_input("Username")
        remove_user_button = st.form_submit_button("Remove User")

    if remove_user_button:
        try:
            delete_user(connection, del_username)
            st.success("User removed successfully!")
            reload = st.button("Reload Page")
            if reload:
                st.experimental_rerun()

        except Exception as e:
            st.error(f"User removal failed: {e}")

    # Assign/Revoke roles form
    with st.form("change_role_form"):
        st.subheader("Assign/Revoke Role")
        role_username = st.text_input("Username")
        roles = ["CONNECT", "RESOURCE", "DBA", "SELECT", "INSERT", "UPDATE", "DELETE", "EXECUTE"]
        role = st.selectbox("Role", roles)
        action = st.selectbox("Action", ["GRANT", "REVOKE"])
        object_name = None
        if role in ["SELECT", "INSERT", "UPDATE", "DELETE", "EXECUTE"]:
            object_name = st.text_input("Object Name (Table or Procedure)")
        change_role_button = st.form_submit_button("Submit")

    if change_role_button:
        try:
            change_user_role(connection, role_username, role, action, object_name)
            action = action.lower()
            st.success(f"{action}ed role successfully!")

            reload = st.button("Reload Page")
            if reload:
                st.experimental_rerun()
        except Exception as e:
            st.error(f"{action}ing role failed: {e}")

# Define the Streamlit app
def app():
    st.set_page_config(page_title="Oracle DataBeast")
    
    # If the user is not logged in, display the login form in the main area
    if not st.session_state.get("logged_in"):
        st.title("Oracle DataBeast Login")
        # Create a form for entering database connection details
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        hostname = st.text_input("Hostname")
        port = st.text_input("Port")
        sid = st.text_input("SID")
        
        # Create a button to initiate database connection
        connect_button = st.button("Connect")

        # Check if the Connect button is clicked
        if connect_button:
            try:
                # Connect to the Oracle database
                connection = create_connection(username, password, hostname, port, sid)

                # Display success message and store the connection in session state
                st.success("Connection successful!")
                st.session_state.connection = connection
                st.session_state.username = username
                st.session_state.logged_in = True
                st.session_state.hostname = hostname 
                st.session_state.sid = sid
                st.session_state.port = port
                
                # Reload the app to hide the login form
                st.experimental_rerun()

            except Exception as e:
                # Display error message if connection fails
                st.error(f"Connection failed: {e}")
    else:
        # Display the username of the logged-in user in the sidebar
        st.sidebar.text_input("Logged in as:", value=st.session_state.username, disabled=True)

        st.sidebar.title("User Options")
        option = st.sidebar.selectbox("Select an option", 
                                      ["Help",
                                       "Diagnosis and Report Generation", 
                                       "Indexing", 
                                       "Tablespace and Partition Management", 
                                       "Query Optimization",
                                       "User Management",
                                       "Manage Tables"])

        # Display the selected option
        st.write(f"You selected: {option}")

        # Call the function corresponding to the selected option
        if option == "Diagnosis and Report Generation":
            diagnosis_report(st.session_state.connection)
        elif option == "Indexing":
            indexing(st.session_state.connection)
        elif option == "Tablespace and Partition Management":
            tablespace_partition(st.session_state.connection)
        elif option == "Query Optimization":
            query_optimization()
        elif option == "User Management":
            user_management(st.session_state.connection)
        elif option == "Manage Tables":
            manage_tables(st.session_state.connection)
        elif option == "Help":
            help_page()

# Run the app
if __name__ == '__main__':
    if st.session_state.get("logged_in"):
        app()
    else:
        app()
