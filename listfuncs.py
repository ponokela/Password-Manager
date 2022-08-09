def listtostring(list, delim):
    return delim.join(list)

def stringtolist(string, delim):
    return list(string.split(delim))
