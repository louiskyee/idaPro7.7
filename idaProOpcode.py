# %%
import os
import sys
import json
import time
import argparse
import subprocess
import multiprocessing
import pandas as pd

from tqdm import tqdm

DEFAULT_INPUT_PATH = r""
DEFAULT_REPORT_PATH = r""
DEFAULT_OUTPUT_FOLDER = r""
DEFAULT_SCRIPT_PATH = r""
DEFAULT_IDAT_PATH = r""
DEFAULT_IDAT64_PATH = r""

# %%
class idaPro(object):
    def __init__(self):
        '''
        Initialize default values for various parameters
        '''
        self.datasetPath = DEFAULT_INPUT_PATH   # Default input dataset folder path
        self.reportPath = DEFAULT_REPORT_PATH   # Default output report folder path
        self.scriptPath = DEFAULT_SCRIPT_PATH   # Default ida pro get opcode script file path
        self.outputFolder = DEFAULT_OUTPUT_FOLDER   # Default output opcode txt file folder path
        self.idat = DEFAULT_IDAT_PATH      # Default idat.exe path
        self.idat64 = DEFAULT_IDAT64_PATH  # Default idat64.exe path
        self.df = pd.DataFrame()                # Default dataframe, used to store file name and architecture

    def run(self):
        if 'ipykernel' not in sys.modules:
            self.parameter_parser()
        self.get_all_files_in_directory()
        self.idaPro_disassemble()
        self.clear_folder()

    def parameter_parser(self):
        '''
        A method for parsing command line parameters
        using `python argparse`.
        '''
        parser = argparse.ArgumentParser(description="Parse command line parameters.")

        parser.add_argument("--input-folder", "-i",
                            dest="input_folder",
                            nargs="?",
                            default=DEFAULT_INPUT_PATH,
                            help="Input dataset folder."
                            )
        parser.add_argument("--report-path", "-r",
                            dest="report_path",
                            nargs="?",
                            default=DEFAULT_REPORT_PATH,
                            help="Input report folder."
                            )
        parser.add_argument("--script-path", "-s",
                            dest="script_path",
                            nargs="?",
                            default=DEFAULT_SCRIPT_PATH,
                            help="Input ida pro python script file path."
                            )
        parser.add_argument("--output-folder", "-o",
                            dest="output_folder",
                            nargs="?",
                            default=DEFAULT_OUTPUT_FOLDER,
                            help="Output opcode txt file folder path."
                            )
        parser.add_argument("--idat-path", "-idat",
                            dest="idat_path",
                            nargs="?",
                            default=DEFAULT_IDAT_PATH,
                            help="Input idat.exe path."
                            )
        parser.add_argument("--idat64-path", "-idat64",
                            dest="idat64_path",
                            nargs="?",
                            default=DEFAULT_IDAT64_PATH,
                            help="Input idat64.exe path."
                            )
        args = parser.parse_args()

        # Save the 'args' parameter in the 'avclass' class
        self.datasetPath = args.input_folder
        self.reportPath = args.report_path
        self.scriptPath = args.script_path
        self.outputFolder = args.output_folder
        self.idat = args.idat_path
        self.idat64 = args.idat64_path

    def get_all_files_in_directory(self):
        '''
        Get all files in the folder and its subfolders, and save them in self.df[filePath]
        Get architecture from report file, and save them in self.df[architecture]
        Get CPU type from report file, and save them in self.df[cpuType]
        '''
        filePaths = []
        architectures = []
        cpuTypes = []
        allFiles = list(os.walk(self.datasetPath))
        for root, dirs, files in tqdm(allFiles, desc="Get all files"):
            for file in files:
                # Get the file extension
                _, file_extension = os.path.splitext(file)
                # Check if the file has an extension (not empty)
                if file_extension:
                    continue  # Skip files with extensions
                file_path = os.path.join(root, file)
                filePaths.append(file_path)
                try:
                    with open(os.path.join(self.reportPath, root[-2:], file + ".json"), encoding="utf-8") as f:
                        data = json.load(f)
                        architectures.append(data["additional_info"]["exiftool"]["CPUArchitecture"])
                        cpuTypes.append(data["additional_info"]["exiftool"]["CPUType"])
                except:
                    architectures.append("Error")
                    cpuTypes.append("Error")
        self.df['filePath'] = filePaths
        self.df['architecture'] = architectures
        self.df['cpuType'] = cpuTypes

    def runIdat(self, row):
        try:
            fileName = os.path.basename(row['filePath'])
            command = []

            if row['architecture'] == "32 bit":
                command = [self.idat, '-c', '-A', f'-S{self.scriptPath} {os.path.join(self.outputFolder, fileName + ".txt")}', row['filePath']]
            elif row['architecture'] == "64 bit":
                command = [self.idat64, '-c', '-A', f'-S{self.scriptPath} {os.path.join(self.outputFolder, fileName + ".txt")}', row['filePath']]

            if command:
                # Run the IDAT command and capture the output
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()

                if process.returncode == 0:
                    # IDAT command ran successfully
                    # Process the output if needed
                    pass
                else:
                    # IDAT command encountered an error
                    self.log_error(row['filePath'], f"IDAT command failed with error: {stderr}")
            else:
                with open('noArchitecture.log', 'a') as log_file:
                    log_file.write(f"No architecture: {row['filePath']}\n")

        except Exception as e:
            self.log_error(row['filePath'], f"An error occurred: {str(e)}")

    def log_error(self, file_path, error_message):
        # Log the error to an error log file
        with open('error.log', 'a') as log_file:
            log_file.write(f"Error ({file_path}): {error_message}\n")    

    def idaPro_disassemble(self):
        start_time = time.time()  # Record the start time

        # Get the number of CPU cores, which can be adjusted as needed
        num_processes = multiprocessing.cpu_count()

        # Create a process pool
        with multiprocessing.Pool(processes=num_processes) as pool:
            data_list = [row for _, row in self.df.iterrows()]

            # Use the pool's map method to process data in parallel
            result_iterator = list(tqdm(pool.imap(self.runIdat, data_list), total=len(data_list)))

        end_time = time.time()  # Record the end time
        execution_time = end_time - start_time  # Calculate the execution time
        with open('time.txt', 'w') as time_file:
            time_file.write(f"Execution Time: {execution_time} seconds")
    
    def clear_folder(self):
        '''
        Clear the input folder
        '''
        for root, dirs, files in os.walk(self.datasetPath):
            for file in files:
                # Get the file extension
                _, file_extension = os.path.splitext(file)
                # Check if the file has an extension (not empty)
                if file_extension:
                    os.remove(os.path.join(root, file))

# %%
if __name__ == "__main__":
    idaPro().run()


