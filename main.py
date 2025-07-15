import sys
from process_dumper import ProcessDumper


def main():

    if len(sys.argv) < 2:
        print("Provide dump path")
        exit(0)

    file_path = sys.argv[1]
    dumper = ProcessDumper(file_path)

    dumper.run()

if __name__ == "__main__":
    main()