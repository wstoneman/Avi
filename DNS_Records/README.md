# Infoblox DNS Record Manipulation

Script Developed by: William Stoneman</br>


## Table of Contents
1.	[Introduction](#Introduction)
1.	[Installation](#Installation)
1.	[Requirements](#Requirements)
1.	[Execution](#Execution)
1.	[Considerations](#Considerations)





# Introduction

The purpose of these scripts are to allow the automation of the creation and deletion of DNS A records on an Infoblox appliance. There are two scripts available:

* **Custom Infoblox DNS Profile** - This script can be used to automate the creation/deletion of DNS A records on an Infoblox appliance, when a VS is created/deleted.
* **Infoblox DNS Controlscript** - This script can be used to automate the creation/deletion of DNS A records on an Infoblox applaince, when a VS is disabled/enabled.

For an overview of the setup and execution of the scripts, please see the Installation and Execution sections below.

# Installation

### DNS Profile

1. Download the Custom Infoblox DNS Profile and save it with a .py extension.
2. Navigate to Templates > Profiles > Custom IPAM/DNS on the Avi Controllers UI and click create.
3. Provide a name for the profile and upload the python script.
4. Create the following script paremeters and provide appropriate values for the environment:</br>
	* A. **username:** Infoblox username.
	* B. **password:** Infoblox password. Select Sensiteve checkbox for security.
	* C. **host:** Infoblox appliance IP or FQDN.
	* D. **wapi_version:** Api version for Infoblox appliance. If unsire, default to "1.2".
5. Click save to create the Custom IPAM/DNS Profile.
6. navigate to Templates > Profiles > IPAM/DNS Profiles on the Avi Controller UI and click create > DNS Profile.
7. Provide the following information for the profile:
	* A. **Name:** A name for the new custom DNS Profile.
	* B. **Type:** Select "Custom DNS".
	* C. **Custom IPAM/DNS Profile:** Select the Custom DNS Profile created earlier from the dropdown.
	* D. **Usable Domain:** 
		* i. **Add Usable Domain:** Add the domains that the VS are configured with and are present on the Infoblox appliance.
		* ii. **Add Script Param:** Add the following Script Parameters.
			* -- network_view | Value: default
			* -- dns_view | Value: default
8. Click save to create the IPAM/DNS Profile.

### DNS Controlscript

1. Download the Infoblox DNS Controlscript.
2. Navigate to Operations > Alerts > Alert Actions on the Avi Controller UI and click create.
3. Provide the following information for the profile:
	* A: **Name:** A name for the new Alert Action.
	* B. **Alert Level:** Provide an alert level for this type of action. I set it as High, to differentiate it from the other noise.
	* C. **Controlscript:** From the dropdown, select "Create new Controlscript Profile".
		* i. **ControlScript Profile:**
			* -- **Name:** A name for the new Controlscript Profile.
			* -- **Controlscript:** Paste the contents of the downloaded Infoblox DNS Controlscript that was downloaded in step 1.
		* -- Click save. 
4. Click save to create the Alert Action.
5. Naviate to Operations > Alerts > Alert Config on the Avi Controller UI and click create.
	### Disable VS Alert
	6. Provide the following information for the configuration:
		* A. **Name:** A name for the new Alert.
		* B. **Throttle Alert:** Set this to 0, so that if multiple VS are disabled at the same time, it will not throttle any alerts.
		* C. **Object*:* Set this to Virtual Service.
		* D. **Instances:** Leave this as "All Instances".
		* E. **Event Occur:** Select "VS Down" from the drop down list.
		* F. **Alert Action:** Select the Alert Action created in steps 3-4.
	7. Click save to create the Alert.
	### Enable VS Alert
	6. Provide the following information for the configuration:
		* A. **Name:** A name for the new Alert.
		* B. **Throttle Alert:** Set this to 0, so that if multiple VS are enabled at the same time, it will not throttle any alerts.
		* C. **Object:** Set this to Virtual Service.
		* D. **Instances:** Leave this as "All Instances".
		* E. **Event Occur:** Select "VS UP" from the drop down list.
		* F. **Alert Action:** Select the Alert Action created in steps 3-4.
	7. Click save to create the Alert.

		# Requirements

The following prerequisites are required to successfully utilize this Workflow:

## Create/Delete Infoblox A Recods on VS Creation/Deletion
* The only requirement is the Custom Infoblox DNS Profile script found in this folder.

## Create/Delete Infoblox A Recods on VS Disabled/Enabled
* The only requirement is the Infoblox DNS Controlscript script found in this folder.

**[Back to top](#table-of-contents)**


# Execution

### DNS Profile

The flow of Actions for this script are:

1.	The Avi Controller will provide the script with the Record Info (ip address and FQDN), as well as the aparemeters set in the profile (username, password, host and wapi_version)
3.	Based on the operation - VS Creation or Deletion, the appropriate function will be executed in the script.
4.	The api call for the Creation or Deletion will be created and executed.
5. Based on the output of the API call, the script will provide either a Successful Execution Notification or an Error Message.

### DNS Controlscript

The flow of Actions for this script are:

1. The Avi Controller will provide the script with the Alert Output (ip address and FQDN). It does not provide Pre configured Perameters, so the Infoblox credentials will need to be hard coded. (these will need to be updated to accomodate the desired configuration).
3. Based on the operation - VS Disabled or Enabled, the appropriate function will be executed in the script.
4. The script will first do an API call to the local host to collect and parse the VS Object. This is to retrieve the current DNS configuration. This action utilizes the API Token from the Alert Output.
4. The api call for the Creation or Deletion will be created and executed.
5. Based on the output of the API call, the script will provide either a Successful Execution Notification or an Error Message.


**[Back to top](#table-of-contents)**

# Considerations

The following are considerations that need to be understood when utilizing these scripts:

* These scripts are designed for an environment utilizing Infoblox for DNS services. This script can easily be altered to support other DNS services, and the underlying design will still function.

**[Back to top](#table-of-contents)**




