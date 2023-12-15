#region imports
import json
import time
from globals import m365_pw
import subprocess
import pandas as pd
import os
import pytz
from geoip2 import database
from pandas.errors import EmptyDataError
import uuid
from datetime import datetime, timedelta
#endregion

class O365Auditor():
    '''Explain Class'''
    def __init__(self, config):
        self.config = config
        self.folder_path = config.get('folder_path')
        self.pages_path = config.get('pages_path')
        self.powerbi_backend_path = config.get('powerbi_backend_path')
        self.pw=config.get('m365_pw')
        self.raw_path=config.get('raw_data_path')
        self.login_command = f'''$secpasswd = ConvertTo-SecureString '{self.pw}' -AsPlainText -Force
            $o365cred = New-Object System.Management.Automation.PSCredential ("ariel-admin@dowbuilt.com", $secpasswd)
            Connect-ExchangeOnline -Credential $o365cred'''
    # region helper
    def df_to_excel(self, df, path):
        '''exports data into excel for user to view'''
        df.to_excel(path, index=False)  # Export the DataFrame to an Excel file
        print(f"DataFrame exported to {path}")
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
                print(f'Failed to {action} {file_path}. Reason: {e}')

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
            print(f'just waited {check_interval} seconds')
            elapsed_time += check_interval
        print("File not found or is empty after waiting")
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
        '''flattens dict'''
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self.flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    items.extend(self.flatten_dict(item, f"{new_key}{sep}{i}", sep=sep).items())
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
    def analyze_ips_in_timeframe(self, df, hours, min_unique_ips, min_unique_states, scenario_str):
        '''looks for flags through df data'''
        results = []
        last_report_times = {}  # Dictionary to track the last report time for each user    

        for i in range(len(df)):
            user_id = df.iloc[i]["Resulting Usr"]
            start_time = df.iloc[i]['CreationDate']

            # Convert UTC to PST
            utc_time = pd.to_datetime(df.iloc[i]['CreationDate'])
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
                    print('FAILED: ', unique_ip_list)   

                if len(set(ip_states)) >= min_unique_states:
                    unique_id = str(uuid.uuid4())
                    report = []
                    for ip in unique_ip_list:
                        ip_data = ip_data_dict[ip]
                        try:
                            ip_state = ip_data.get('state', "XX")
                            rownums = relevant_rows.index[relevant_rows['ClientIP'] == ip].tolist()
                            if len(ip_state) != 2:
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
                                    'Start Time': readable_start_time,
                                    'User': user_id,
                                    'ip_count': len(report),
                                    'location_count':(len(location)),
                                    'location_list': location,
                                    'Report': report,
                                    'uuid':unique_id, })  

                    last_report_times[user_id] = start_time  # Update the last report time for the user 

        return results
            # Function to flatten the nested structures
    def parse_datetime(self, time_str):
        '''parses teh date times for the results, needs to work with PST which is a string and doesnt parse well'''
        # Remove the 'PST' part and parse the datetime
        time_str = time_str.replace(' PST', '')
        dt = datetime.strptime(time_str, '%m/%d/%Y %I:%M %p')
        # Set the timezone to Pacific Time
        pacific = pytz.timezone('America/Los_Angeles')
        return pacific.localize(dt)
    # endregion
    def basic_pwrshl_grab_raw(self, startdate, enddate):
            '''explain'''
            self.path = f"{self.pages_path}\AuditLogResults_Page1.csv"
            self.commands = f'''{self.login_command}
                $ExportPath = "{self.path}"
                $Results = Search-UnifiedAuditLog -StartDate "{startdate} 00:00:00" -EndDate "{enddate} 00:00:00" -Operations "UserLoggedIn", "UserLoginFailed" -ResultSize 5000 -SessionCommand ReturnLargeSet 
                $Results | Export-Csv -Path $ExportPath
                '''

            self.p = subprocess.run(
                    ["powershell", "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", self.commands],
                    capture_output=True,
                    text=True
                )
    def paginated_pwrshl_grab_raw(self, startdate, enddate, pageNumber = 1, delete_old_files = True):
        '''set up to grab all data within date range into seperate .csvs that get combined at the end'''
        unique_id = uuid.uuid1()
        sessionId = f"AuditLogSession-{unique_id}"  # Unique session ID
        moreData = True

        # start be clearing what was previously in this folder
        if delete_old_files:
            self.action_to_files_in_folder(self.pages_path, 'delete')

        while moreData:
            exportPath = f"{self.pages_path}\AuditLogResults_Page{pageNumber}.csv"

            self.commands = f'''{self.login_command}
                $ExportPath = "{exportPath}"
                $Results = Search-UnifiedAuditLog -StartDate "{startdate} 00:00:00" -EndDate "{enddate} 00:00:00" -Operations "UserLoggedIn", "UserLoginFailed" -ResultSize 1000 -SessionId "{sessionId}" -SessionCommand ReturnLargeSet
                $Results | Export-Csv -Path $ExportPath
                '''
            self.p = subprocess.run(
                    ["powershell", "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", self.commands],
                    capture_output=True,
                    text=True
                )

            if self.wait_for_file(exportPath):
                # Check if the maximum number of entries was returned
                total_rows = int(self.create_df(exportPath).to_dict(orient='records')[0]['ResultCount'])
                current_row = int(self.create_df(exportPath).to_dict(orient='records')[-1]['ResultIndex'])
                # current_row = (pageNumber)*1000+1
                moreData = total_rows > current_row
                print(f"Page {pageNumber}: {current_row} rows out of {total_rows}")
                if moreData == True:
                    pageNumber += 1
            else:
                print("ERROR: Bad argument did not produce a file")
                moreData= False

        print('~DONE~ @ Page', pageNumber)
        self.df_created = pd.concat([self.create_df(csv) for csv in self.action_to_files_in_folder(self.pages_path, 'grab path from')]).sort_values(by='CreationDate')
        # have to drop duplicate b/c "add two weeks" creates a date overlap
        self.df_created = self.df_created.drop_duplicates(subset=['CreationDate', 'UserIds', 'Operations','AuditData','Identity'])
        
        # Combine all CSV files into one
        if total_rows <= 50000:
            self.report_path = f"{self.folder_path}\AuditLogFull.csv"
            self.df_created.to_csv(self.report_path, index=False)

        else:
            earliest_existing_date = self.df_created.iloc[-1]['CreationDate'][:self.df_created.iloc[-1]['CreationDate'].find(' ')]
            earliest_existing_date = self.add_two_weeks(earliest_existing_date)
            # grab the next 50000 rows
            self.paginated_pwrshl_grab_raw(startdate, earliest_existing_date, pageNumber, False)
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
        filtered_df = df[df["Actor_1_ID"] != ""]

        # Creating a dictionary with unique "Actor_1_ID" as keys and corresponding "Actor_0_ID" as values
        actor_dict = dict(zip(filtered_df["Actor_0_ID"], filtered_df["Actor_1_ID"]))

        def replace_actor_id(row):
            if row["Actor_1_ID"] == "":
                return actor_dict.get(row["Actor_0_ID"], row["Actor_1_ID"])
            return row["Actor_1_ID"]

        df["Actor_1_ID"] = df.apply(replace_actor_id, axis=1)
        df["Resulting Usr"] = df["Actor_1_ID"].copy()
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
            print(f"Processing user: {usr}")

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
                min_unique_ips=4, 
                min_unique_states=1, 
                scenario_str="IP Variance")) 
        return results
    def order_results(self, results):
        '''explain'''
        sorted_data = sorted(results, key=lambda x: self.parse_datetime(x['Start Time']))
        return sorted_data
    def transform_for_powerbi(self, results):
        '''power bi wants FLAT TABLE data, and so this will do that'''
        flattened_data= []

        for entry in oa.ordered_results:
            for report in entry['Report']:
                flattened_data.append({
                    'Scenario': entry['Scenario'],
                    'Start Time': entry['Start Time'],
                    'User': entry['User'],
                    'ip_count': entry['ip_count'],
                    'location_count': entry['location_count'],
                    'location_list': ', '.join(entry['location_list']),
                    'logins': report['logins'],
                    'report_location': report['location'],
                    'ip': report['ip'],
                    'report_uuid': report['uuid'],
                    'user_uuid': entry['uuid']
                })
        
        return flattened_data
    def run(self, starddate, enddate):
        self.paginated_pwrshl_grab_raw(starddate, enddate)
        self.df_flattened = self.flatten_df_data(self.df_created)
        self.df_w_ip = self.add_ip_columns(self.df_flattened)
        self.df_w_all_usrs = self.expose_ios_users(self.df_w_ip)
        self.results = self.audit_by_user(self.df_w_all_usrs)
        self.ordered_results = self.order_results(self.results)
        self.powerbi_data = self.transform_for_powerbi(self.ordered_results)
        self.df_to_excel(pd.DataFrame(self.powerbi_data), self.powerbi_backend_path)

if __name__ == "__main__":
    config = {
        'm365_pw': m365_pw,
        'folder_path': r"C:\Egnyte\Shared\IT\o365 Security Audit\Programatic Audit Log Results",
        'pages_path':r"C:\Egnyte\Shared\IT\o365 Security Audit\Programatic Audit Log Results\Audit Log Pages",
        'powerbi_backend_path':r"C:\Egnyte\Shared\IT\o365 Security Audit\audit_data_for_analysis.xlsx"
        # 'bamb_token': bamb_token,
        # 'b2token': bamb2_token,
        # 'smartsheet_token':smartsheet_token,
    }

    oa = O365Auditor(config)
    oa.run('12/10/2023', '12/16/2023')