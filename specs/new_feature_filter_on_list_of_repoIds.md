Lets add a new feature to filter the findings for a specific list of repoIds.

The user can now run this in 2 modes: 
* run for all fidnings- This is what we do now and no changes
* run for findings from a specific list of repos
    * The user can provide an OPTIONAL input in the .env file calls LIST_OF_REPO_IDS
* the user will specify which mode using a variable in the .env file: FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS
    * if this is set to True - run for list of repos defined in LIST_OF_REPO_IDS
