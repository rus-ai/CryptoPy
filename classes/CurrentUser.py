from win32api import CloseHandle, GetCurrentThread, GetCurrentProcess
from win32security import OpenThreadToken, OpenProcessToken, GetTokenInformation, TokenUser
from win32security import LookupAccountSid, ConvertSidToStringSid, TOKEN_QUERY


class CurrentUser:
    def __init__(self):
        try:
            token = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1)
        except:
            token = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)
        sid, _ = GetTokenInformation(token, TokenUser)
        CloseHandle(token)
        self.sid = ConvertSidToStringSid(sid)
        self.username, self.domain, _ = LookupAccountSid(None, sid)

    def __repr__(self):
        return f"{self.domain}\\{self.username} (SID: {self.sid})"
