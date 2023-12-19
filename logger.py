from datetime import datetime
import os
import sys
import inspect
import time

class ghetto_logger:
    '''to deploy in class, put self.log=ghetto_logger("<module name>.py"), then ctr f and replace print( w/ self.log.log('''
    def __init__(self, title, print = True):
        raw_now = datetime.now()
        self.print= print
        self.now = raw_now.strftime("%m/%d/%Y %H:%M:%S")
        self.first_use=True
        self.first_line_stamp  = f"{self.now}  {title}--"
        self.start_time = time.time()
        if os.name == 'nt':
            current_file_path = os.path.abspath(__file__)
            directory = os.path.dirname(current_file_path)
            logger_name = 'log.txt'
            self.path = os.path.join(directory, logger_name)
        else:
            self.path ="log.txt"

    def timestamp(self): 
        '''creates a string of minute/second from start_time until now for logging'''
        end_time = time.time()  # get the end time of the program
        elapsed_time = end_time - self.start_time  # calculate the elapsed time in seconds       

        minutes, seconds = divmod(elapsed_time, 60)  # convert to minutes and seconds       
        timestamp = "{:02d}:{:02d}".format(int(minutes), int(seconds))
        
        return timestamp
    
    def log(self, text, type = "new_line", mode="a"):
        # so lists/dictionaries/etc can be logged without issue
        text = str(text)

        function_name = inspect.currentframe().f_back.f_code.co_name
        
        try:
            module_name = inspect.getmodule(inspect.stack()[1][0]).__name__
        except:
            module_name = "__main__"

        func_stamp = f"{self.timestamp()}  {module_name}.{function_name}(): "

        if self.print == True:
            print(f"{func_stamp} {text}")

        with open(self.path, mode=mode) as file:
            if self.first_use == True:
                file.write("\n" + "\n"+ self.first_line_stamp)
                self.first_use = False
            if self.first_use == False and type == "paragraph":
                file.write(text)
            elif self.first_use == False:
                file.write("\n  " + func_stamp + text)