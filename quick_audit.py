#region imports
import json
import time
from globals import m365_pw, smartsheet_token
import subprocess
import pandas as pd
import os
import pytz
from geoip2 import database
import smartsheet
from pandas.errors import EmptyDataError
import uuid
from datetime import datetime, timedelta
from logger import ghetto_logger
from smartsheet_grid import grid
#endregion

class O365Auditor():
    '''Explain Class'''
    def __init__(self, config):
        self.config = config
        self.folder_path = config.get('folder_path')
        self.smartsheet_token = config.get('smartsheet_token')
        self.pages_path = config.get('pages_path')
        self.powerbi_backend_path = config.get('powerbi_backend_path')
        self.email=config.get('email')
        self.pw=config.get('m365_pw')
        self.log=ghetto_logger("quick_audit.py")
        self.raw_path=config.get('raw_data_path')
        self.sheetid=config.get('ss_gui_sheetid')
        self.operation = ', '.join([f'"{item}"' for item in config.get('operations')])
        self.login_command = f'''$secpasswd = ConvertTo-SecureString '{self.pw}' -AsPlainText -Force
            $o365cred = New-Object System.Management.Automation.PSCredential ("{self.email}", $secpasswd)
            Connect-ExchangeOnline -Credential $o365cred'''
        grid.token=smartsheet_token
        self.smart = smartsheet.Smartsheet(access_token=self.smartsheet_token)
        self.smart.errors_as_exceptions(True)
        self.us_state_abbreviations = [
            "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
            "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
            "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
            "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
            "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"
        ]
        
    #region helper
    def df_to_excel(self, df, path):
        '''exports data into excel for user to view'''
        df.to_excel(path, index=False)  # Export the DataFrame to an Excel file
        self.log.log(f"DataFrame exported to {path}")
    def action_to_files_in_folder(self, folder_path, action):
        '''delete used in audit log pages to save space
        grab path from used to make master audit list'''
        file_paths = []  # Initialize a list to store file paths

        # List all files and directories in the folder
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    if action == "delete":
                        os.remove(file_path)  # Remove the file
                    elif action == "grab path from":
                        file_paths.append(file_path)  # Append the file path to the list
            except Exception as e:
                self.log.log(f'Failed to {action} {file_path}. Reason: {e}')

        if action == "grab path from":
            return file_paths  # Return the list of file paths
    def wait_for_file(self, file_path, timeout=10, check_interval=5):
        """
        Wait for a file to exist and contain data, up to a certain timeout.
        file_path: path to the file to check
        timeout: total time to wait in seconds
        check_interval: time between checks in seconds
        """
        elapsed_time = 0
        while elapsed_time < timeout:
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                return True  # File exists and has content
            time.sleep(check_interval)
            self.log.log(f'just waited {check_interval} seconds')
            elapsed_time += check_interval
        self.log.log("File not found or is empty after waiting")
        return False  # Timeout reached
    def create_df(self, path):
        '''grabs df from csv and promotes headers'''
        try:
            df = pd.read_csv(path, header=None, skiprows=1)
            new_header = df.iloc[0]  # Grab the first row for the header
            df = df[1:]  # Take the data less the header row
            df.columns = new_header
            return df
        except EmptyDataError:
            return 
    def add_two_weeks(self, str):
        '''I dont trust the incomplete o365 audit reports, it seems they do not come out cleanly by date, but in date clusters. this goes two weeks back for pagination w/ redundancy'''
        # Example date string

        # Convert the string to a datetime object
        date_object = datetime.strptime(str, '%m/%d/%Y')

        # Add two weeks (14 days)
        new_date_object = date_object + timedelta(days=14)

        # Convert back to string if needed
        new_date_str = new_date_object.strftime('%m/%d/%Y')

        return new_date_str
    def flatten_dict(self, d, parent_key='', sep='_'):
        '''flattends dict, k is current key, v is value, d is dict, sep seperates the key from the number. parent key helps with recursion'''
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            # print(f"Key: {k}, Value: {v}, New Key: {new_key}")  # Print current key, value, and new key
            if isinstance(v, dict):
                items.extend(self.flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    # print(f"List item: {item}, Type: {type(item)}")  # Print each item in the list and its type
                    if isinstance(item, dict):
                        items.extend(self.flatten_dict(item, f"{new_key}{sep}{i}", sep=sep).items())
                    else:
                        items.append((f"{new_key}{sep}{i}", item))
            else:
                items.append((new_key, v))
        return dict(items)
    def find_ip_details(self, ip):
        '''checks IP against db by geolite'''
        # Load the GeoIP2 database
        reader = database.Reader(r"C:\Egnyte\Shared\IT\o365 Security Audit\GeoLite2-City_20231208\GeoLite2-City.mmdb")  

        if ip == '':
            return {'state':'No IP Given', 'city':'No IP Given', 'country': 'No IP Given', 'IP':ip} 

        # Check if the string is an IPv4 with a port or an IPv6 address
        if ip.count(':') > 1:
            # IPv6 address (no port handling needed)
            pass
        else:
            # IPv4 address, possibly with a port
            ip = ip.split(':')[0]   

        # Lookup an IP address
        response = reader.city(ip)
        # state = response.subdivisions.most_specific.name
        iso_code = response.subdivisions.most_specific.iso_code
        result = {'state':iso_code, 'city':response.city.name, 'country': response.country.name, 'IP':ip}
        return result   
    def convert_df_utc_to_pst(self, df):
        '''Convert 'CreationDate' from UTC to PST in the DataFrame'''
        # Create a copy of the DataFrame to avoid SettingWithCopyWarning
        df_copy = df.copy() 

        # Define the PST timezone
        pst_timezone = pytz.timezone('US/Pacific')  

        # Function to convert each row
        def convert_row(row):
            utc_time = pd.to_datetime(row['CreationDate'])
            utc_time_localized = utc_time.tz_localize('UTC')
            pst_time = utc_time_localized.tz_convert(pst_timezone)
            return pst_time.strftime('%m/%d/%Y %I:%M %p') + " PST"  

        # Check if 'CreationDate' column exists in the DataFrame
        if 'CreationDate' in df_copy.columns:
            # Apply the conversion to each row
            df_copy['CreationDate_PST'] = df_copy.apply(convert_row, axis=1)
        else:
            # Handle the case where 'CreationDate' is not in the DataFrame
            print("Column 'CreationDate' not found in DataFrame.")
            return None  # Explicitly return None if the column is not found    

        return df_copy  # Return the modified DataFrame
    def analyze_ips_in_timeframe(self, df, hours, min_unique_ips, min_unique_states, scenario_str):
        '''looks for flags through df data'''
        results = []
        last_report_times = {}  # Dictionary to track the last report time for each user

        # Grouping the DataFrame by 'Operation' column
        grouped_df = df.groupby('Operation')

        for operation, group_df in grouped_df:
            for i in range(len(group_df)):
                user_id = group_df.iloc[i]["Resulting Usr"]
                start_time = group_df.iloc[i]['CreationDate']
                

                # Convert UTC to PST
                utc_time = pd.to_datetime(group_df.iloc[i]['CreationDate'])
                utc_time_localized = utc_time.tz_localize('UTC')
                pst_timezone = pytz.timezone('US/Pacific')
                pst_time = utc_time_localized.tz_convert(pst_timezone)

                readable_start_time= pst_time.strftime('%m/%d/%Y %I:%M %p') + " PST"   



                # Check if the user has a recent report within the timeframe
                if user_id in last_report_times and (start_time - last_report_times[user_id]).total_seconds() / 3600 < hours:
                    continue  # Skip to the next row if within the timeframe    

                end_time = start_time + pd.Timedelta(hours=hours)
                relevant_rows = df[(df['CreationDate'] >= start_time) & (df['CreationDate'] <= end_time)]
                unique_ip_list = [ip for ip in relevant_rows['ClientIP'].unique() if ip != '']  

                if len(unique_ip_list) >= min_unique_ips:
                    try:
                        ip_data_dict = {ip: self.find_ip_details(ip) for ip in unique_ip_list}
                        ip_states = [ip_data_dict[ip]['state'] for ip in unique_ip_list]
                    except:
                        self.log.log('FAILED: ', unique_ip_list)  

                    if len(set(ip_states)) >= min_unique_states:
                        unique_id = str(uuid.uuid4())
                        report = []
                        for ip in unique_ip_list:
                            ip_data = ip_data_dict[ip]
                            try:
                                ip_state = ip_data.get('state', "XX")
                                rownums = relevant_rows.index[relevant_rows['ClientIP'] == ip].tolist()
                                if ip_state not in self.us_state_abbreviations:
                                    country = ip_data['country']
                                    report.append({'logins': len(rownums), "location": country, "ip":ip, "uuid":unique_id})
                                    # report.append(f"{len(rownums)} Logins || {country}: {ip}")
                                else:
                                    report.append({'logins': len(rownums), "location": ip_state, "ip":ip, "uuid":unique_id})
                                    # report.append(f"{len(rownums)} Logins || {ip_state}: {ip}")
                            except TypeError:
                                rownums = relevant_rows.index[relevant_rows['ClientIP'] == ip].tolist()
                                country = ip_data['country']
                                report.append({'logins': len(rownums), "location": country, "ip":ip, "uuid":unique_id})
                                # report.append(f"{len(rownums)} Logins || {country}: {ip}")
                        location = []
                        for item in report:
                            if item['location'] not in location:
                                location.append(item['location'])

                        results.append({'Scenario': scenario_str,
                                        'Operation': operation,
                                        'Start Time': readable_start_time,
                                        'User': user_id,
                                        'ip_count': len(report),
                                        'location_count': len(location),
                                        'location_list': location,
                                        'Report': report,
                                        'uuid': unique_id})

                        last_report_times[user_id] = start_time  # Update the last report time for the user

        return results
    def analyze_foreign_ips(self, df, hr=24):
        '''pulls out foreign IP addresses (as a flag) over a specified timeframe (defualting to 24 hour segments)'''
        results = []
        last_report_times = {}  # To track the last report time for each user

        # Create a copy of the DataFrame to avoid SettingWithCopyWarning
        df_copy = df.copy()

        # Convert UTC to PST
        df_copy['PSTCreationDate'] = pd.to_datetime(df_copy['CreationDate']).dt.tz_localize('UTC').dt.tz_convert('US/Pacific')

        # Grouping the DataFrame by 'Operation' column
        grouped_df = df_copy.groupby('Operation')

        for operation, group_df in grouped_df:
            # only used for user logged in action
            if operation == 'UserLoggedIn':
                for i in range(len(group_df)):
                    user_id = group_df.iloc[i]["Resulting Usr"]
                    start_time = group_df.iloc[i]['PSTCreationDate']
                    readable_start_time = start_time.strftime('%m/%d/%Y %I:%M %p') + " PST"

                    # Skip if the user has a recent report within the timeframe
                    if user_id in last_report_times and (start_time - last_report_times[user_id]).total_seconds() / 3600 < hr:
                        continue

                    end_time = start_time + pd.Timedelta(hours=hr)
                    relevant_rows = df_copy[(df_copy['PSTCreationDate'] >= start_time) & (df_copy['PSTCreationDate'] <= end_time)]

                    foreign_ips = []
                    for ip in relevant_rows['ClientIP'].unique():
                        if ip != '':
                            try:
                                ip_details = self.find_ip_details(ip)
                                if ip_details.get('state') not in self.us_state_abbreviations:
                                    foreign_ips.append({'ip': ip, 'details': ip_details})
                            except Exception as e:
                                self.log.log(f'Error fetching IP details for {ip}: {e}')

                    if foreign_ips:
                        unique_id = str(uuid.uuid4())
                        report = [{'ip': ip_info['ip'], 'location': ip_info['details'].get('country', 'Unknown'), 'logins':1, 'uuid': unique_id}
                                  for ip_info in foreign_ips]

                        results.append({'Scenario': 'foriegn IP',
                                        'Operation': operation,
                                        'Start Time': readable_start_time,
                                        'User': user_id,
                                        'ip_count': len(report),
                                        'location_count': 1,
                                        'location_list': [instance['location'] for instance in report],
                                        'Report': report,
                                        'uuid': unique_id})

                        last_report_times[user_id] = start_time  # Update last report time

        return results

    def parse_datetime(self, time_str):
        '''parses teh date times for the results, needs to work with PST which is a string and doesnt parse well'''
        # Remove the 'PST' part and parse the datetime
        time_str = time_str.replace(' PST', '')
        dt = datetime.strptime(time_str, '%m/%d/%Y %I:%M %p')
        # Set the timezone to Pacific Time
        pacific = pytz.timezone('America/Los_Angeles')
        return pacific.localize(dt)
    def return_unique_posting_data(self, primary, reference, fields_to_compare):
        '''makes sure not to repost to ss rows that are already there
        the primary checks if any of its rows (on specific fields) are already existing in reference''' 

        # Function to create a comparable version of an item
        def make_comparable(item):
            return {field: item[field] for field in fields_to_compare}  

        # Create a set of comparable items from the reference dataset
        reference_comparable = {frozenset(make_comparable(item).items()) for item in reference} 

        # Filter out duplicates and collect unique data
        unique_posting_data = []
        for item in primary:
            item_comparable = frozenset(make_comparable(item).items())
            if item_comparable not in reference_comparable:
                unique_posting_data.append(item)    

        return unique_posting_data
    def get_surrounding_days(self, date_str):
        '''explain'''
        date_obj = datetime.strptime(date_str, "%m/%d/%Y")
        # Calculating yesterday's date (the day before today)
        startdate = date_obj - timedelta(days=2)

        # Calculating tomorrow's date (the day after today)
        enddate = date_obj + timedelta(days=2)

        # Formatting the dates as mm/dd/yyyy
        formatted_startdate = startdate.strftime("%m/%d/%Y")
        formatted_enddate = enddate.strftime("%m/%d/%Y")
        return formatted_startdate, formatted_enddate 
    def filter_df_for_report(self, df, usr, ip_list, ip_mode):
        '''filters df for activity report by only looking at the correct user and correct ips'''
        '''takes the 'self.df_w_all_usrs' and filteres the ips & not availables before continuing'''
        usr_filtered_df = df[(df['Resulting Usr'].str.lower() == str(usr).lower()) | (df['Resulting Usr'] == "Column missing")]
        if ip_mode == "exclude":
            ip_filtered_df = usr_filtered_df[~usr_filtered_df['ActorIpAddress'].isin(ip_list)]
        elif ip_mode == "include":
            ip_filtered_df = usr_filtered_df[usr_filtered_df['ActorIpAddress'].isin(ip_list)]

        return usr_filtered_df
    # endregion
    #region grab data
    def basic_pwrshl_grab_raw(self, startdate, enddate, usr):
            '''explain'''
            self.path = f"{self.pages_path}\AuditLogResults_Page1.csv"
            self.commands = f'''{self.login_command}
                $ExportPath = "{self.path}"
                $Results = Search-UnifiedAuditLog -StartDate "{startdate} 14:00:00" -EndDate "{enddate} 02:00:00" -ResultSize 5000 -SessionCommand ReturnLargeSet -UserIds "Not Available", "{usr}" 
                $Results | Export-Csv -Path $ExportPath
                '''

            self.p = subprocess.run(
                    ["powershell", "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", self.commands],
                    capture_output=True,
                    text=True
                )
    def paginated_pwrshl_grab_raw(self, startdate, enddate, pageNumber=1):
        '''This function loops through each date segment if the date range is more than 62 days, then combines all data into one csv
        this handles the 50,000 row limit on data 
        (b/c the data is not ordered by date so I can't just pull 50,000 rows and then start at the oldest date)'''
        # Clearing previous files (to prep for new request)
        self.action_to_files_in_folder(self.pages_path, 'delete')

        # Convert string dates to datetime objects
        start_date = datetime.strptime(startdate, "%m/%d/%Y")
        end_date = datetime.strptime(enddate, "%m/%d/%Y")
        readable_start_date = startdate
        while start_date < end_date:
            segment_end_date = min(start_date + timedelta(days=61), end_date)
            # self.log.log("Processing segment starting at:", start_date, " end date: ", end_date, ' seg_end_date: ', segment_end_date)
            self.log.log(f'processing segment {readable_start_date}-{datetime.strptime(str(segment_end_date), "%Y-%m-%d %H:%M:%S").strftime("%m/%d/%Y")}')
            # Process the segment

            unique_id = uuid.uuid1()
            sessionId = f"AuditLogSession-{unique_id}"
            pageNumber = self.process_segment(start_date, segment_end_date, pageNumber, sessionId)
            pageNumber += 1
            self.log.log(" ")
            # Break the loop if we've reached the end date
            if segment_end_date >= end_date:
                break

            # Update start date for the next segment
            start_date = segment_end_date
            readable_start_date = datetime.strptime(str(segment_end_date), "%Y-%m-%d %H:%M:%S").strftime("%m/%d/%Y")

        self.log.log('~DONE loading data~')
        self.df_created = pd.concat([self.create_df(csv) for csv in self.action_to_files_in_folder(self.pages_path, 'grab path from')]).sort_values(by='CreationDate')
        self.df_created = self.df_created.drop_duplicates(subset=['CreationDate', 'UserIds', 'Operations','AuditData','Identity'])

        # Combine all CSV files into one
        # self.report_path = f"{self.folder_path}\AuditLogFullRaw.csv"
        # self.df_created.to_csv(self.report_path, index=False)
    def process_segment(self, start_date, end_date, pageNumber, sessionId):
        '''This loops through each date segment, grabbing the data in 1000 row increments, setting up a page for each increment'''
        moreData = True
        total_rows = 0

        while moreData:
            exportPath = f"{self.pages_path}/AuditLogResults_Page{pageNumber}.csv"

            # Running PowerShell command
            self.run_powershell_command(start_date, end_date, exportPath, sessionId)

            if self.wait_for_file(exportPath):
                df = self.create_df(exportPath)
                total_rows = int(df.to_dict(orient='records')[0]['ResultCount'])
                current_row = int(df.to_dict(orient='records')[-1]['ResultIndex'])
                moreData = total_rows > current_row
                self.log.log(f"Page {pageNumber}: {current_row} rows out of {total_rows}")

                if moreData:
                    pageNumber += 1
            else:
                self.log.log("ERROR: Bad argument did not produce a file")
                moreData = False
            
        return pageNumber
    def run_powershell_command(self, start_date, end_date, exportPath, sessionId):
        '''powershell that does the audit, gets looped many time over by handlers'''
        commands = f'''{self.login_command}
            $ExportPath = "{exportPath}"
            $Results = Search-UnifiedAuditLog -StartDate "{start_date.strftime('%m/%d/%Y')} 00:00:00" -EndDate "{end_date.strftime('%m/%d/%Y')} 00:00:00" -Operations {self.operation} -ResultSize 1000 -SessionId "{sessionId}" -SessionCommand ReturnLargeSet
            $Results | Export-Csv -Path $ExportPath
            '''
        time.sleep(2)
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", commands], capture_output=True, text=True)
    #endregion
    #region process data
    def flatten_df_data(self, df):
        '''the main data is in a nested dictionary in "AuditData" column'''
        data = df.to_dict(orient='records')

        # Convert the 'AuditData' field from JSON to a dictionary and update the original dictionary with these values
        for record in data:
            audit_data = json.loads(record['AuditData'])
            record.update(audit_data)

        # Apply flattening to each record
        flattened_data = [self.flatten_dict(record) for record in data]

        # Create DataFrame from flattened data
        df = pd.DataFrame(flattened_data)

        # not flattening, but had to happen, to remove NaN
        df.fillna('', inplace=True)
        return df
    def add_ip_columns(self, df):
        '''explain'''
        df['IP State'] = df['ClientIP'].apply(lambda x: self.find_ip_details(x).get('state', 'Unknown'))
        df['IP Country'] = df['ClientIP'].apply(lambda x: self.find_ip_details(x).get('country', 'Unknown'))
        return df
    def expose_ios_users(self, df):
        '''actions on ios hides the userid, but can be found in actor id''' 
        if 'Actor_1_ID' in df.columns:
            filtered_df = df[df["Actor_1_ID"] != ""]    
            # Creating a dictionary with unique "Actor_1_ID" as keys and corresponding "Actor_0_ID" as values
            actor_dict = dict(zip(filtered_df["Actor_0_ID"], filtered_df["Actor_1_ID"]))    

            def replace_actor_id(row):
                # If Actor_1_ID is empty, use UserIds
                if row["Actor_1_ID"] == "" or row["Actor_1_ID"] == "Not Available":
                    return actor_dict.get(row["Actor_0_ID"], row["Actor_1_ID"])
                return row["Actor_1_ID"]    

            df["Actor_1_ID"] = df.apply(replace_actor_id, axis=1)
            df["Resulting Usr"] = df["Actor_1_ID"].copy()
        else:
            # If Actor_1_ID column doesn't exist, use UserIds for Resulting Usr
            df["Resulting Usr"] = df["UserIds"]

        return df
    def audit_by_user(self,df):
        '''goes through each user and audits their data given specific audit scenarios, also appends their user to a list'''
        
        # sort and process creation date to set up the audit (by date/time)
        df = df.sort_values(by='CreationDate')
        df['CreationDate'] = pd.to_datetime(df['CreationDate'])

        # seperate per user
        self.dfs = {}
        for user_id in df["Resulting Usr"].unique():
            self.dfs[user_id] = df[df["Resulting Usr"] == user_id]

        # analyse per user
        results = []
        self.usrs = []
        for usr in self.dfs:
            self.usrs.append(usr)
            self.log.log(f"Processing user: {usr}")

            # location variance audit
            results.extend(self.analyze_ips_in_timeframe(
                df=self.dfs[usr], 
                hours=8, 
                min_unique_ips=3, 
                min_unique_states=2, 
                scenario_str="Location Variance"))
            
            # ip variance audit
            results.extend(self.analyze_ips_in_timeframe(
                df=self.dfs[usr], 
                hours=3, 
                min_unique_ips=5, 
                min_unique_states=1, 
                scenario_str="IP Variance")) 
            
            results.extend(self.analyze_foreign_ips(
                df=self.dfs[usr]
            ))

        self.log.log(f"processed {len(self.dfs)} users")
        return results
    def order_results(self, results):
        '''explain'''
        sorted_data = sorted(results, key=lambda x: self.parse_datetime(x['Start Time']))
        return sorted_data
    def transform_for_dataprocessing(self, results):
        '''power bi wants FLAT TABLE data, and so this will do that'''
        flattened_data= []

        for entry in results:
            for report in entry['Report']:
                flattened_data.append({
                    'Scenario': entry['Scenario'],
                    'Operation': entry['Operation'],
                    'Start Time': entry['Start Time'],
                    'User': entry['User'],
                    'ip count': entry['ip_count'],
                    'location count': entry['location_count'],
                    'location list': ', '.join(entry['location_list']),
                    'report login count': report['logins'],
                    'report location': report['location'],
                    'report ip': report['ip'],
                    'HIDE_report uuid': report['uuid']
                })
        
        return flattened_data
    def prep_ss_post(self, data):
        '''post data is needs to be any data the report came back with that is not already on ss'''
        self.gridsheet = grid(self.sheetid)
        self.gridsheet.fetch_content()
        sheet_data = self.gridsheet.df.to_dict(orient="records")

        # Finding duplicates
        fields_to_compare = ['Start Time', 'User', 'location list']
        self.ss_posting_data = self.return_unique_posting_data(self.processing_data, sheet_data, fields_to_compare)

        self.log.log(f'posting: {self.ss_posting_data}')

        return self.ss_posting_data
    #endregion
    #region run helpers
    def audit_login_data(self, df):
        '''these functions are only good for login data, not other types'''
        self.audit_results = self.audit_by_user(df)
        self.ordered_results = self.order_results(self.audit_results)
        self.processing_data = self.transform_for_dataprocessing(self.ordered_results)
        return self.processing_data
    def post_audit_findings(self, df):
        '''posts audit findings to smartsheet'''
        self.ss_post_data = self.prep_ss_post(self.processing_data)
        try:
            self.gridsheet.post_new_rows(self.ss_post_data)
        except IndexError:
            # if self.ss_post_data is empty
            pass
        self.gridsheet.handle_update_stamps()
    #endregion
    def run(self, starddate, enddate):
        '''main audit engine'''
        self.paginated_pwrshl_grab_raw(starddate, enddate)
        self.df_flattened = self.flatten_df_data(self.df_created)
        self.df_w_ip = self.add_ip_columns(self.df_flattened)
        self.df_w_all_usrs = self.expose_ios_users(self.df_w_ip)
        self.df_to_excel(self.df_w_all_usrs, r"C:\Egnyte\Shared\IT\o365 Security Audit\Programatic Audit Log Results\AuditLogFullProcessed.xlsx")
        self.audit_login_data(self.df_w_all_usrs)
    def run_recent(self):
        '''grabs yesterday and tomorrow for run's inputs'''
        today_date = datetime.now().strftime("%m/%d/%Y")
        formatted_yesterday, formatted_tomorrow = self.get_surrounding_days(today_date)
        self.run(formatted_yesterday, formatted_tomorrow)
        self.post_audit_findings(self.processing_data)

    def run_activity_report(self, activity_date, usr, ip_list = [], ip_mode = 'exclude'):
        '''to explore suspicious activity of specific user on specific day
        ip_mode will either be exclude or include, to search for SPECIFIC ip, or all ip EXCEPT specific one'''
        startdate, enddate = self.get_surrounding_days(activity_date)
        print(f'working on time segment {startdate}-{enddate}')
        self.action_to_files_in_folder(self.pages_path, 'delete')
        self.basic_pwrshl_grab_raw(startdate, enddate, usr)
        self.df_created = pd.concat([oa.create_df(csv) for csv in oa.action_to_files_in_folder(oa.pages_path, 'grab path from')]).sort_values(by='CreationDate')
        self.df_flattened = self.flatten_df_data(self.df_created)
        self.df_w_ip = self.add_ip_columns(self.df_flattened)
        self.df_w_all_usrs = self.expose_ios_users(self.df_w_ip)
        self.filtered_df = self.filter_df_for_report(self.df_w_all_usrs, usr, ip_list, ip_mode)
        final_df = self.convert_df_utc_to_pst(self.filtered_df)
        self.df_to_excel(final_df, r'C:\Egnyte\Shared\IT\o365 Security Audit\Programatic Audit Log Results\ActivityReport.xlsx')

if __name__ == "__main__":
    config = {
        'm365_pw': m365_pw,
        'folder_path': r"C:\Egnyte\Shared\IT\o365 Security Audit\Programatic Audit Log Results",
        'pages_path':r"C:\Egnyte\Shared\IT\o365 Security Audit\Programatic Audit Log Results\Audit Log Pages",
        'powerbi_backend_path':r"C:\Egnyte\Shared\IT\o365 Security Audit\audit_data_for_analysis.xlsx",
        # 'operations':['Reset user password.', 'Set force change user password.', 'Change user password.']
        # 'operations': ['UserLoggedIn', 'UserLoginFailed'],
        'operations': ['UserLoggedIn', 'New-InboxRule', 'Set-InboxRule'],
        'smartsheet_token':smartsheet_token,
        'ss_gui_sheetid': 4506324192677764,
        'email': 'ariel-admin@dowbuilt.com'
    }

    oa = O365Auditor(config)
    # For using existing data
    # oa.df_created = pd.concat([oa.create_df(csv) for csv in oa.action_to_files_in_folder(oa.pages_path, 'grab path from')]).sort_values(by='CreationDate')
    # oa.df_created = pd.read_csv(r"C:\Egnyte\Shared\IT\o365 Security Audit\Programatic Audit Log Results\AuditLogFull.csv")
    # oa.run('09/01/2023', '12/28/2023')
    oa.run_recent()
    # oa.run_activity_report('12/27/2023', 'arielv@dowbuilt.com')

