import sys
import os
sys.path.append(os.path.dirname(__file__))
from db_writer import NIDSDatabaseWriter

if __name__ == "__main__":
    writer = NIDSDatabaseWriter()
    writer.init_database()
    print(" Database tables and views created successfully.")