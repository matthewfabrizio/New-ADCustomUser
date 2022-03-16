# New-ADCustomUser

Custom Active Directory user creation based on JSON configuration data.

This script was designed to create user accounts for students. The source data comes from a student information system (SIS). I thought about packaging this as a module, but I'm torn on what is easier to comprehend to others.

## Overview

This script utilizes data from a source and creates users in an on-premise Active Directory.

This script is not finished but the main goals are listed below.

### CSV

- Automatically export user data from the source every night into a CSV file.
- Create custom user data based on values in CSV.

### User Data

- User data formed from the CSV values is then used to validate against Active Directory user data.
- The users are matched by two fields
  - employeeID (1st)
  - UserPrincipalName (2nd)
- If there is an employeeID/UPN match, then validate that users data and make any changes
  - These changes include demographic data and also data such as the distinguishedName. (see the config file UserProperties to see what gets modified)
- If employeeID/UPN do not match, then create the user.

### Inactive Users (WIP)

- Any users who exist in Active Directory but are not found in the source file will be moved to a disabled users organizational unit and disabled.

### Azure Active Directory Sync (WIP)

- Once users are modified/created, directory sync these users.

### Google Cloud Directory Sync (WIP)

- Once users are modified/created, sync with Google Workspace

### Reset User Passwords (WIP)

- Once the GCDS sync runs, user passwords need to be updated in order for the passwords to actually sync. Hopefully this changes in the future.
