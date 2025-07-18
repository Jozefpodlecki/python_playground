import logging
import os
import sys
from process_dumper import ProcessDumper
from pe_analyser import PeAnalyser

def main():
    logging.basicConfig(
        level = logging.INFO,
        format = "%(asctime)s [%(levelname)s] %(message)s",
    )

    handler = logging.FileHandler("dumper.log")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger = logging.getLogger(__name__)

    if len(sys.argv) < 2:
        logger.error("Provide file path")
        exit(0)

    file_path = sys.argv[1]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # dumper = ProcessDumper(file_path)
    # dumper.run(script_dir)

    analyser = PeAnalyser(file_path)
    analyser.dump_functions("functions.txt")
    # analyser.dump_text_section("text_section.asm")
    # analyser.dump_data_section("data_section.bin")

if __name__ == "__main__":
    main()