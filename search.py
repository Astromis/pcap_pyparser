def search_hex_string(request, packet):
    #For hex search request must begig with 'h'
    data = packet['data']
    hex_request = ''
    string_for_search = ''
    if request[0] == 'h':
        for i in range(len(data)):
            tmp = hex(ord(data[i]))[2:]
            if len(tmp) < 2:
                tmp = '0' + tmp
            string_for_search += tmp
        if string_for_search.find(request[1:].lower()) != -1:
            return data
    else:
        for i in range(len(request)):
            tmp = hex(ord(request[i]))[2:]
            if len(tmp) < 2:
                tmp = '0' + tmp
            hex_request += tmp
        for i in range(len(data)):
            tmp = hex(ord(data[i]))[2:]
            if len(tmp) < 2:
                tmp = '0' + tmp
            string_for_search += tmp
        if string_for_search.find(hex_request.lower()) != -1:
            return data
