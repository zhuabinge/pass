this module is to load the config file.


This module will set correspondent types of tags on configuration files which
aim at building http data.First, it will find the tags starting with '$' on the files, e.g. $url_dmn.
Second, it will set a distinctive numbers for each tags, representing their different types.
Finally, if types are regex-matching ones, it will generate correspondent patterns for regex matching.
