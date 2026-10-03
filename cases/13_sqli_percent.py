import sqlite3

def find_order(conn, order_id):
    cur = conn.cursor()
    query = "SELECT * FROM orders WHERE id = '%s'" % order_id
    cur.execute(query)
    return cur.fetchall()
