#region imports
import json
import time
from globals import m365_pw
import subprocess
import pandas as pd
import os
import pytz
from geoip2 import database
#endregion

class O365Auditor():
    '''Explain Class'''
    def __init__(self, config):
        self.config = config
        self.folder_path = config.get('folder_path')
        self.dev_path = config.get('dev_path')
        self.pages_path = config.get('pages_path')
        self.report_path = config.get('report_path')
        self.pw=config.get('m365_pw')
        self.raw_path=config.get('raw_data_path')
        self.login_command = f'''$secpasswd = ConvertTo-SecureString '{self.pw}' -AsPlainText -Force
            $o365cred = New-Object System.Management.Automation.PSCredential ("ariel-admin@dowbuilt.com", $secpasswd)
            Connect-ExchangeOnline -Credential $o365cred'''
    # region helper
    def wait_for_file(self, file_path, timeout=60, check_interval=5):
        """
        Wait for a file to exist and contain data, up to a certain timeout.
        file_path: path to the file to check
        timeout: total time to wait in seconds
        check_interval: time between checks in seconds
        """
        elapsed_time = 0
        while elapsed_time < timeout:
            print(elapsed_time, timeout)
            print(os.path.exists(file_path), os.path.getsize(file_path))
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                return True  # File exists and has content
            time.sleep(check_interval)
            print(f'just waited {check_interval} seconds')
            elapsed_time += check_interval
        print("File not found or is empty after waiting")
        return False  # Timeout reached
    def df_to_excel(self, df, path):
        '''exports data into excel for user to view'''
        df.to_excel(path, index=False)  # Export the DataFrame to an Excel file
        print(f"DataFrame exported to {path}")
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
            pst_timezone = pytz.timezone('US/Pacific')
            pst_time = utc_time.dt.tz_convert(pst_timezone)

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
                    report = []
                    for ip in unique_ip_list:
                        ip_data = ip_data_dict[ip]
                        try:
                            ip_state = ip_data.get('state', "XX")
                            rownums = relevant_rows.index[relevant_rows['ClientIP'] == ip].tolist()
                            if len(ip_state) != 2:
                                country = ip_data['country']
                                report.append(f"{country}: {ip} (Rows: {rownums})")
                            else:
                                report.append(f"{len(rownums)} Logins || {ip_state}: {ip}")
                        except TypeError:
                            report.append(f"Type ERROR: {ip_data}") 

                    results.append({'Scenario': scenario_str,
                                    'Start Time': readable_start_time,
                                    'User': user_id,
                                    'Report': report})  

                    last_report_times[user_id] = start_time  # Update the last report time for the user 

        return results
            # Function to flatten the nested structures
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
            print(self.p.stdout, self.p.stderr, self.commands)
    def old_paginated_pwrshl_grab_raw(self, startdate, enddate):
        sessionId = "AuditLogSession"  # Unique session ID
        pageNumber = 1
        moreData = True
        csv_files = []

        while moreData:
            exportPath = f"{self.pages_path}\AuditLogResults_Page{pageNumber}.csv"

            self.commands = f'''{self.login_command}
                $ExportPath = "{exportPath}"
                $Results = Search-UnifiedAuditLog -StartDate "{startdate} 00:00:00" -EndDate "{enddate} 00:00:00" -Operations "UserLoggedIn", "UserLoginFailed" -ResultSize 5000 -SessionId "{sessionId}" -SessionCommand ReturnLargeSet
                $Results | Export-Csv -Path $ExportPath
                '''

            self.p = subprocess.run(
                    ["powershell", "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", self.commands],
                    capture_output=True,
                    text=True
                )

            # Check if the maximum number of entries was returned
            if len(self.p.stdout.splitlines()) < 5001:  # Adjust as necessary
                moreData = False  # No more data to paginate through
            else:
                pageNumber += 1

        # Combine all CSV files into one
        combined_df = pd.concat([pd.read_csv(f) for f in csv_files])
        self.report_path = f"{self.folder_path}\AuditLogFull.csv"
        combined_df.to_csv(self.report_path, index=False)

        # Optionally, delete the individual files
        for f in csv_files:
            os.remove(f)
    def paginated_pwrshl_grab_raw(self, startdate, enddate):
        '''set up to grab all data within date range into seperate .csvs that get combined at the end'''
        sessionId = "AuditLogSession"  # Unique session ID
        pageNumber = 1
        moreData = True
        csv_files = []

        # while moreData:
        exportPath = f"{self.pages_path}\AuditLogResults_Page{pageNumber}.csv"
        self.commands = f'''{self.login_command}
            $ExportPath = "{exportPath}"
            $Results = Search-UnifiedAuditLog -StartDate "{startdate} 00:00:00" -EndDate "{enddate} 00:00:00" -Operations "UserLoggedIn", "UserLoginFailed" -ResultSize 5000 -SessionId "{sessionId}" -SessionCommand ReturnLargeSet
            $Results | Export-Csv -Path $ExportPath
            '''
        self.p = subprocess.run(
                ["powershell", "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", self.commands],
                capture_output=True,
                text=True
            )
        
        print(self.p.stdout, self.p.stderr, self.commands)
        #     if self.wait_for_file(exportPath):
        #         # Check if the maximum number of entries was returned
        #         total_rows = self.create_df(exportPath).to_dict(orient='records')[0]['ResultCount']
        #         current_row = pageNumber*5000+1
        #         moreData = total_rows < current_row
        #         print(total_rows, current_row, moreData)
        #         if moreData == True:
        #             pageNumber += 1
        #             print('now page number is ', pageNumber)
        # print('DONE at page ', pageNumber)
        # # Combine all CSV files into one
        # combined_df = pd.concat([pd.read_csv(f) for f in csv_files])
        # self.report_path = f"{self.folder_path}\AuditLogFull.csv"
        # combined_df.to_csv(self.report_path, index=False)

        # # Optionally, delete the individual files
        # for f in csv_files:
        #     os.remove(f)
    def create_df(self, path):
        '''grabs df from csv and promotes headers'''
        df = pd.read_csv(path, header=None, skiprows=1)
        new_header = df.iloc[0]  # Grab the first row for the header
        df = df[1:]  # Take the data less the header row
        df.columns = new_header
        return df
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
        '''explain'''
        
        # sort and process creation date to set up the audit (by date/time)
        df = df.sort_values(by='CreationDate')
        df['CreationDate'] = pd.to_datetime(df['CreationDate'])

        # seperate per user
        dfs = {}
        for user_id in df["Resulting Usr"].unique():
            dfs[user_id] = df[df["Resulting Usr"] == user_id]

        # analyse per user
        results = []
        for usr in dfs:
            print(f"Processing user: {usr}")

            # location variance audit
            results.extend(self.analyze_ips_in_timeframe(
                df=dfs[usr], 
                hours=8, 
                min_unique_ips=3, 
                min_unique_states=2, 
                scenario_str="Location Variance"))
            
            # ip variance audit
            results.extend(self.analyze_ips_in_timeframe(
                df=dfs[usr], 
                hours=3, 
                min_unique_ips=4, 
                min_unique_states=1, 
                scenario_str="IP Variance")) 
        return results
    
    def run(self, starddate, enddate):
        self.paginated_pwrshl_grab_raw(starddate, enddate)
        # self.basic_pwrshl_grab_raw(starddate, enddate)
        # self.df_created = self.create_df(self.report_path)
        # self.df_flattened = self.flatten_df_data(self.df_created)
        # self.df_w_ip = self.add_ip_columns(self.df_flattened)
        # self.df_w_all_usrs = self.expose_ios_users(self.df_w_ip)
        # self.results = self.audit_by_user(self.df_w_all_usrs)

if __name__ == "__main__":
    config = {
        'm365_pw': m365_pw,
        'folder_path': r"C:\Egnyte\Shared\IT\o365 Security Audit\Programatic Audit Log Results",
        'pages_path':r"C:\Egnyte\Shared\IT\o365 Security Audit\Programatic Audit Log Results\Audit Log Pages"
        # 'bamb_token': bamb_token,
        # 'b2token': bamb2_token,
        # 'smartsheet_token':smartsheet_token,
    }

    oa = O365Auditor(config)
    oa.run('11/13/2023', '12/01/2023')