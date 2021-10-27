class ConnectionConfig:
    def __init__(self, args):
        self.username = args.username

        # impacket needs the unset values to be equal to ''
        self.password = args.password if args.password else ''
        self.nt_hash = args.nt_hash if args.nt_hash else ''

        self.domain = args.domain
        self.timeout = args.timeout