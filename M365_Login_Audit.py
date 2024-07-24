#region imports
import os
import sys
import smartsheet
from pandas.errors import EmptyDataError
from smartsheet.exceptions import ApiError
from datetime import datetime, timedelta
from geoip2 import database
import pandas as pd
import requests
import subprocess
import pytz
import json
import time
import uuid

# Check if we are on a dev computer or server
if os.name == 'nt':
    sys.path.append(r"Z:\Shared\IT\Projects and Solutions\Python\Ariel\_Master")
else:
    sys.path.append(os.path.expanduser(r"~/_Master"))

# Import master_logger, master_smartsheet_grid, and master_globals
try:
    from master_logger import ghetto_logger
    from master_smartsheet_grid import grid
    from master_globals import m365_microsoftlogs_pw, smartsheet_automation_token, mcgraph_secret
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)
#endregion

# powershell installs:
# Install-Module -Name ExchangeOnlineManagement -AllowClobber
# Install-Module -Name MSAL.PS -Scope CurrentUser
# Install-Module -Name Microsoft.Graph -Scope CurrentUser

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
        self.mcgraph_secret=config.get('mcgraph_secret')
        self.log=ghetto_logger("quick_audit.py")
        self.raw_path=config.get('raw_data_path')
        self.sheetid=config.get('ss_gui_sheetid')
        self.empl_list_sheetid= config.get('empl_list_sheetid')
        self.operation = ', '.join([f'"{item}"' for item in config.get('operations')])
        self.exchange_login_command = f'''$secpasswd = ConvertTo-SecureString '{self.pw}' -AsPlainText -Force
            $o365cred = New-Object System.Management.Automation.PSCredential ("{self.email}", $secpasswd)
            Connect-ExchangeOnline -Credential $o365cred'''
        self.mcgraph_login_command = f'''$tenantId = "01076a3f-5feb-4a23-a79d-59395d396366"
            $clientId ="c3a411cb-af0b-4f4a-87af-a6b92be9beeb"
            $clientSecret ="{self.mcgraph_secret}"
            $secureClientSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
            $token = Get-MsalToken -TenantId $tenantId -ClientId $clientId -ClientSecret $secureClientSecret
            $accessToken = ConvertTo-SecureString -String $token.AccessToken -AsPlainText -Force
            Connect-MgGraph -AccessToken $accessToken'''
        grid.token=self.smartsheet_token
        self.smart = smartsheet.Smartsheet(access_token=self.smartsheet_token)
        self.smart.errors_as_exceptions(True)
        self.us_state_abbreviations = [
            "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
            "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
            "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
            "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
            "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"
        ]
        self.entra_ids_grabbed = False
        
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
        reader = database.Reader(r"Z:\Shared\IT\Projects and Solutions\o365 Security Audit\GeoLite2-City_20231208\GeoLite2-City.mmdb")  

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
                                if ip_details.get('state') not in self.us_state_abbreviations and ip_details.get('country', 'Unknown') != "United States":
                                    # had to write exception for david simon :/, maybe we should have a list of exceptions?
                                    if user_id.lower() != "davids@dowbuilt.com" and ip_details.get('country', 'Unknown') != "Thailand":
                                        foreign_ips.append({'ip': ip, 'details': ip_details})
                            except Exception as e:
                                self.log.log(f'Error fetching IP details for {ip}: {e}')

                    if foreign_ips:
                        unique_id = str(uuid.uuid4())
                        report = [{'ip': ip_info['ip'], 'location': ip_info['details'].get('country', 'Unknown'), 'logins':1, 'uuid': unique_id}
                                  for ip_info in foreign_ips]

                        results.append({'Scenario': 'Foreign IP',
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
    def get_surrounding_days(self, date_str, surrounding_day_number):
        '''it takes a date, and sourrounding day number, and returns a start and end date, 
        such that the stard and end date are each X days from the origin, where x is the surrounding day number'''
        date_obj = datetime.strptime(date_str, "%m/%d/%Y")
        # Calculating yesterday's date (the day before today)
        startdate = date_obj - timedelta(days=surrounding_day_number)

        # Calculating tomorrow's date (the day after today)
        enddate = date_obj + timedelta(days=surrounding_day_number)

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
    def basic_pwrshl_grab_raw(self, startdate, enddate, usr=''):
            '''used as a template to understand how the main data pull goes (that gets looped & paginated)'''
            if usr != "":
                results = f'Search-UnifiedAuditLog -StartDate "{startdate} 14:00:00" -EndDate "{enddate} 02:00:00" -ResultSize 5000 -SessionCommand ReturnLargeSet -UserIds "Not Available", "{usr}"'
            else:
                print('no usrs')
                results = f'Search-UnifiedAuditLog -StartDate "{startdate} 14:00:00" -EndDate "{enddate} 02:00:00" -ResultSize 5000 -SessionCommand ReturnLargeSet' 
            self.path = f"{self.pages_path}\AuditLogResults_Page1.csv"
            self.commands = f'''{self.exchange_login_command}
                $ExportPath = "{self.path}"
                $Results = {results} 
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
        try:
            self.df_created = pd.concat([self.create_df(csv) for csv in self.action_to_files_in_folder(self.pages_path, 'grab path from')]).sort_values(by='CreationDate')
        except ValueError:
            self.log.log('ERROR: no data was found with that particular request')

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
        commands = f'''{self.exchange_login_command}
            $ExportPath = "{exportPath}"
            $Results = Search-UnifiedAuditLog -StartDate "{start_date.strftime('%m/%d/%Y')} 00:00:00" -EndDate "{end_date.strftime('%m/%d/%Y')} 00:00:00" -Operations {self.operation} -ResultSize 1000 -SessionId "{sessionId}" -SessionCommand ReturnLargeSet
            $Results | Export-Csv -Path $ExportPath
            '''
        time.sleep(2)
        self.p = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", commands], capture_output=True, text=True)
        print(self.p.stdout)
    #endregion
    #region MFA
    def pwrshl_grab_entraids(self):
        '''use CLI to grab entra ideas which can help with Iphone users and MFA data'''
        self.path = f"{self.folder_path}\MFA\EntraIds.csv"
        self.commands = f'''{self.exchange_login_command}
            {self.mcgraph_login_command}
            $users = Get-MgUser -All -Property "Id, DisplayName, Mail"
            $results = $users | Select-Object Id, DisplayName, Mail
            $ExportPath = "{self.path}"
            $results | Export-Csv -Path $ExportPath
            '''
        self.p = subprocess.run(
                ["powershell", "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", self.commands],
                capture_output=True,
                text=True
            )
        time.sleep(2)
        df = pd.read_csv(self.path)
        # The csv exports with the wrong header!
        data = df.to_dict(orient='dict')
        # Extract the nested dictionary
        nested_dict = data['#TYPE Selected.Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser']

        # Convert the nested dictionary into a list of dictionaries
        records = [{'Id': k[0], 'DisplayName': k[1], 'Mail': v} for k, v in nested_dict.items() if k != ('Id', 'DisplayName')]

        # Create the DataFrame
        self.entra_id_df = pd.DataFrame(records)

        self.entra_ids_grabbed = True
    def pwrshl_grab_mfa_data(self):
        '''use CLI to grab entra ideas which can help with Iphone users and MFA data'''
        self.path = f"{self.folder_path}\MFA\MFA_Log.csv"
        self.commands = f'''{self.exchange_login_command}
            {self.mcgraph_login_command}
            # Get the data
            $results = Get-MgBetaReportAuthenticationMethodUserRegistrationDetail -All
            
            # Select specific properties to export
            $formattedResults = $results | Select-Object Id, IsAdmin, IsMfaCapable, IsMfaRegistered, IsPasswordlessCapable
            
            # Export the formatted data to a CSV file
            $ExportPath = "{self.path}"
            $formattedResults | Export-Csv -Path $ExportPath -NoTypeInformation
            '''
        self.p = subprocess.run(
                ["powershell", "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", self.commands],
                capture_output=True,
                text=True
            )
        time.sleep(2)
        self.mfa_data_df = pd.read_csv(self.path)
    def process_mfa_data(self):
        '''merge the two data sets (entra ids and MFA data that is only organized by id) and then create lists for auditing'''
        # grab empl data
        employee_ss = grid(self.empl_list_sheetid)
        employee_ss.fetch_content()
        empl_email_list = employee_ss.df['emailAsText'].tolist()

        # merge dfs
        self.merged_df = pd.merge(self.mfa_data_df, self.entra_id_df[['Id', 'DisplayName', 'Mail']], on='Id', how='left')
        
        # filter merged df to active empl
        self.merged_df['Mail_lower'] = self.merged_df['Mail'].str.lower()
        empl_email_list_lower = [email.lower() for email in empl_email_list]
        self.active_empl = self.merged_df[self.merged_df['Mail_lower'].isin(empl_email_list_lower)]
        incapable_mfa = self.active_empl[self.active_empl['IsMfaCapable'] == False]
        incapable_db_mfa = [email for email in incapable_mfa['Mail'].tolist() if 'dowbuilt' in email] 
        self.disactivated_mfa_string= ", ".join(incapable_db_mfa)
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
        '''actions on ios hides the userid, but can be found in actor id. EDIT: Now I actualy grab entra ids from pwrshel so it should ALWAYS find the corresponding user given an id''' 
        if 'Actor_1_ID' in df.columns:
            if not self.entra_ids_grabbed:
                self.pwrshl_grab_entraids()
            actor_dict = self.entra_id_df.set_index('Id')['Mail'].to_dict()      

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
                    'HIDE_report uuid': report['uuid'],
                    'Status': 'Unknown'
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

        for data in self.ss_posting_data:
            data['Disabled MFA Accounts'] = ""
        
        if len(self.ss_posting_data) != 0:
            self.ss_posting_data[len(self.ss_posting_data)-1]['Disabled MFA Accounts'] = self.disactivated_mfa_string

        self.log.log(f'posting: {self.ss_posting_data}')

        return self.ss_posting_data
    #endregion
    #region audit helpers
    def audit_login_data(self, df):
        '''these functions are only good for login data, not other types'''
        self.audit_results = self.audit_by_user(df)
        self.ordered_results = self.order_results(self.audit_results)
        self.processing_data = self.transform_for_dataprocessing(self.ordered_results)
        return self.processing_data
    def audit_inboxrules(self, origin_date):
        '''report that shows inbox changes in the last 15 days'''
        self.log.log('exporting inbox rule changes')
        self.config['operations'] = ['New-InboxRule', 'Set-InboxRule']
        self.operation = ', '.join([f'"{item}"' for item in self.config.get('operations')])
        startdate, enddate = self.get_surrounding_days(date_str = origin_date, surrounding_day_number = 15)
        self.grab_login_data(startdate,enddate)
        self.df_to_excel(self.df_w_all_usrs, r"Z:\Shared\IT\Projects and Solutions\o365 Security Audit\Programatic Audit Log Results\InboxRuleChangeLog.xlsx")
    def audit_pw_changes(self, origin_date):
        '''report that shows pw changes in last 30 days'''
        self.log.log('exporting exporting pw changes')
        self.config['operations'] = ['Change user password.', 'Reset user password.', 'Set force change user password.']
        self.operation = ', '.join([f'"{item}"' for item in self.config.get('operations')])
        startdate, enddate = self.get_surrounding_days(date_str = origin_date, surrounding_day_number = 30)
        self.paginated_pwrshl_grab_raw(startdate, enddate)
        self.df_flattened = self.flatten_df_data(self.df_created)
        self.df_flattened['UserIds'] = self.df_flattened['ObjectId']
        self.df_to_excel(self.df_flattened, r"Z:\Shared\IT\Projects and Solutions\o365 Security Audit\Programatic Audit Log Results\PasswordChangeLog.xlsx")
    def audit_mfa_policy(self):
        '''making sure mfa is enforced for current users'''
        self.pwrshl_grab_entraids()
        self.pwrshl_grab_mfa_data()
        self.process_mfa_data()
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
    def grab_login_data(self, startdate, enddate):
        '''main audit engine'''
        self.paginated_pwrshl_grab_raw(startdate, enddate)
        self.df_flattened = self.flatten_df_data(self.df_created)
        self.df_w_ip = self.add_ip_columns(self.df_flattened)
        self.df_w_all_usrs = self.expose_ios_users(self.df_w_ip)
    def audit_routine(self, mode="routine"):
        '''the run script designed to be run daily. runs for two days forward and back, and then posts the findings to smartsheet (that are non duplicate with what is already there)'''
        today_date = datetime.now().strftime("%m/%d/%Y")
        startdate, enddate = self.get_surrounding_days(date_str = today_date, surrounding_day_number = 2)
        self.audit_mfa_policy()
        self.grab_login_data(startdate, enddate)
        self.df_to_excel(self.df_w_all_usrs, r"Z:\Shared\IT\Projects and Solutions\o365 Security Audit\Programatic Audit Log Results\AuditLogFullProcessed.xlsx")
        self.audit_login_data(self.df_w_all_usrs)
        self.post_audit_findings(self.processing_data)
        if mode == "comprehensive":
            self.audit_inboxrules(origin_date = today_date)
            self.audit_pw_changes(origin_date = today_date)

if __name__ == "__main__":
    config = {
        'm365_pw': m365_microsoftlogs_pw, 
        'folder_path': r"Z:\Shared\IT\Projects and Solutions\o365 Security Audit\Programatic Audit Log Results",
        'pages_path':r"Z:\Shared\IT\Projects and Solutions\o365 Security Audit\Programatic Audit Log Results\Audit Log Pages",
        'powerbi_backend_path':r"Z:\Shared\IT\Projects and Solutions\o365 Security Audit\audit_data_for_analysis.xlsx",
        'operations': ['UserLoggedIn'],
        'smartsheet_token':smartsheet_automation_token,
        'ss_gui_sheetid': 4506324192677764,
        'email': 'microsoftlogs@dowbuilt.com',
        'mcgraph_secret':mcgraph_secret,
        'empl_list_sheetid': 5956860349048708
    }

    oa = O365Auditor(config)
    # For using existing data
    # oa.grab_login_data('01/17/2024', '01/21/2024')
    oa.audit_routine()


# To change: remove paths from code
# Add: actor ID to smartsheet
# Add: capture more precise timestamp
