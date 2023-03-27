import {json} from "stream/consumers";

const { Worker } =  require('worker_threads');
const { networkInterfaces } = require('os');
const { promisify } = require('util');
const net = require('net');
const ping = require('ping');
const nmap = require('node-nmap');
const libnmapp = require('libnmap');
nmap.nmapLocation = 'nmap';

// TODO: Create a options menu, with [ Nmap location, Network Subnet ]

// const connectAsync = promisify(net.connect);

// function networkDiscovery(): Promise<string> {
//     return new Promise((resolve, reject) => {
//         let nmapscan = new nmap.OsAndPortScan('192.168.1.69');
//         nmapscan.on('complete', function(data: any){
//             console.log(JSON.stringify(data));
//             resolve('nice');
//         });
//         nmapscan.on('error', function(error: any){
//             console.log(error);
//             reject(error);
//         });
//
//         nmapscan.startScan();
//     });
// }

export async function scanDevices() : Promise<unknown> {
    // TODO: Scan devices and return output
    const testObj = JSON.stringify({
        Addresses: ['192.168.1.1', '192.168.1.2']
    })
    const IP = await getLocalIP();
    console.log('Current IP: ' + IP);
    const ipAddress = IP.split(':')[0];
    const netmask = IP.split(':')[1];

    const addressParts = ipAddress.split('.');
    const netmaskParts = netmask.split('.');
    const netAddress = addressParts.map((part, i) => parseInt(part) & parseInt(netmaskParts[i])).join('.');
    const range = `${netAddress.substring(0, netAddress.lastIndexOf('.'))}.1-254`;
    const ipAddresses: string[] = [];

    let nmapscan = new nmap.QuickScan(range);
    const nmapPromise = new Promise((resolve, reject) => {
        nmapscan.on('complete', function (data: any) {
            // console.log('START OF DEVICE DISCOVERY');
            // console.log(JSON.stringify(data));
            for (let i = 0; i < data.length; i++) {
                if (data[i].mac) {
                    ipAddresses.push(data[i].ip)
                }
            }
            // console.log(ipAddresses);
            resolve(ipAddresses);
        });

        nmapscan.on('error', function (error: any) {
            console.log(error);
            reject(error);
        });
    });

    nmapscan.startScan(); // Start the nmap scan
    let nmapScanResult = await nmapPromise; // Wait for the promise to resolve

    console.log(nmapscan.scanTime);
    // TODO: Error handling
    return nmapScanResult;
}

export async function scanPorts(event: any, devices: string) : Promise<unknown> {
    // TODO: Scan ports and return output
    let mainList: string[] = [];
    for (let i = 0; i < devices.length; i++) {
        console.log('Currently at device: ' + devices[i]);
        mainList.push(devices[i]);
    }
    // mainList = [
    //     '192.168.1.1',   '192.168.1.11',
    //     '192.168.1.69',  '192.168.1.103',
    //     '192.168.1.104', '192.168.1.111',
    //     '192.168.1.133', '192.168.1.161',
    //     '192.168.1.175', '192.168.1.13',
    // ];

    // console.log('DEVICES In PORT SCAN: ');
    // console.log(devices);
    // console.log(typeof devices);
    // console.log(testList)
    // console.log(typeof testList);
    // console.log(mainList)
    // console.log(typeof mainList);


    // let nmapscan = new nmap.OsAndPortScan('192.168.1.13');
    // let nmapscan = new nmap.NmapScan(devices, ['-O', '-sV', '-v']);
    // let nmapscan = new nmap.NmapScan('192.168.1.13', '-sV');


    const opts = {
        flags: [
            '-sV', // Open port to determine service (i.e. FTP, SSH etc)
            '-O', // OS finger printing (requires elevated privileges)
        ],
        range: mainList,
        json: true
    };

    const testReport = {
        "192.168.1.1": {
            "debugging": [{
                "item": {
                    "level": "0"
                }
            }
            ],
            "host": [{
                "address": [{
                    "item": {
                        "addr": "172.30.160.1",
                        "addrtype": "ipv4"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "0"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "Busy server or unknown class",
                        "values": "3B9,3C7,3D5,3E3,3F1,404"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938869",
                    "starttime": "1679938833"
                },
                "os": [{
                    "osmatch": [{
                        "item": {
                            "accuracy": "100",
                            "line": "69956",
                            "name": "Microsoft Windows 10 1809 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "100",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }
                    ],
                    "portused": [{
                        "item": {
                            "portid": "21",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }, {
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "40547",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1016",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1016",
                            "state": "closed"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "21",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "ftp",
                                "servicefp": "SF-Port21-TCP:V=7.91%I=7%D=3/27%Time=6421D518%P=i686-pc-windows-windows%r(NULL,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(GenericLines,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(Help,17C,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n214-The\\x20following\\x20commands\\x20are\\x20recognized\\.\\r\\n\\x20NOP\\x20\\x20USER\\x20TYPE\\x20SYST\\x20SIZE\\x20RNTO\\x20RNFR\\x20RMD\\x20\\x20REST\\x20QUIT\\r\\n\\x20HELP\\x20XMKD\\x20MLST\\x20MKD\\x20\\x20EPSV\\x20XCWD\\x20NOOP\\x20AUTH\\x20OPTS\\x20DELE\\r\\n\\x20CWD\\x20\\x20CDUP\\x20APPE\\x20STOR\\x20ALLO\\x20RETR\\x20PWD\\x20\\x20FEAT\\x20CLNT\\x20MFMT\\r\\n\\x20MODE\\x20XRMD\\x20PROT\\x20ADAT\\x20ABOR\\x20XPWD\\x20MDTM\\x20LIST\\x20MLSD\\x20PBSZ\\r\\n\\x20NLST\\x20EPRT\\x20PASS\\x20STRU\\x20PASV\\x20STAT\\x20PORT\\r\\n214\\x20Help\\x20ok\\.\\r\\n\")%r(GetRequest,76,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n501\\x20What\\x20are\\x20you\\x20trying\\x20to\\x20do\\?\\x20Go\\x20away\\.\\r\\n\")%r(HTTPOptions,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RTSPRequest,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RPCCheck,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSVersionBindReqTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSStatusRequestTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(SSLSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TerminalServerCookie,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TLSSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\");"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "80",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:microsoft:internet_information_server:10.0", "cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "http",
                                "ostype": "Windows",
                                "product": "Microsoft IIS httpd",
                                "version": "10.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "135",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "msrpc",
                                "ostype": "Windows",
                                "product": "Microsoft Windows RPC"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "137",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "netbios-ns"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "no-response",
                                "reason_ttl": "0",
                                "state": "filtered"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "139",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "netbios-ssn",
                                "ostype": "Windows",
                                "product": "Microsoft Windows netbios-ssn"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "445",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "microsoft-ds"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "903",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "tunnel": "ssl",
                                "version": "1.10"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "913",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "version": "1.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "localhost-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "262",
                        "values": "CCAE986C,9BC01D2E,8DC1B4D6,D9EE02FA,FE640F76,817B8490"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "none returned (unsupported)"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "254",
                        "srtt": "135",
                        "to": "100000"
                    }
                }
                ]
            }, {
                "address": [{
                    "item": {
                        "addr": "192.168.1.1",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "78:8A:20:07:C5:37",
                        "addrtype": "mac",
                        "vendor": "Ubiquiti Networks"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "item": {
                    "endtime": "1679938990",
                    "starttime": "1679938833"
                },
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ]
            }
            ],
            "hosthint": [{
                "address": [{
                    "item": {
                        "addr": "192.168.1.1",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "78:8A:20:07:C5:37",
                        "addrtype": "mac",
                        "vendor": "Ubiquiti Networks"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ]
            }
            ],
            "item": {
                "args": "nmap --host-timeout=120s -T4 -sV -O -oX - -p1-1024  192.168.1.1",
                "scanner": "nmap",
                "start": "1679938832",
                "startstr": "Mon Mar 27 10:40:32 2023",
                "version": "7.91",
                "xmloutputversion": "1.05"
            },
            "runstats": [{
                "finished": [{
                    "item": {
                        "elapsed": "159.07",
                        "exit": "success",
                        "summary": "Nmap done at Mon Mar 27 10:43:10 2023; 2 IP addresses (2 hosts up) scanned in 159.07 seconds",
                        "time": "1679938990",
                        "timestr": "Mon Mar 27 10:43:10 2023"
                    }
                }
                ],
                "hosts": [{
                    "item": {
                        "down": "0",
                        "total": "2",
                        "up": "2"
                    }
                }
                ]
            }
            ],
            "scaninfo": [{
                "item": {
                    "numservices": "1024",
                    "protocol": "tcp",
                    "services": "1-1024",
                    "type": "syn"
                }
            }
            ],
            "verbose": [{
                "item": {
                    "level": "0"
                }
            }
            ]
        },
        "192.168.1.103": {
            "debugging": [{
                "item": {
                    "level": "0"
                }
            }
            ],
            "host": [{
                "address": [{
                    "item": {
                        "addr": "172.30.160.1",
                        "addrtype": "ipv4"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "0"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "Incremental",
                        "values": "771,777,77D,783,789,78F"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938878",
                    "starttime": "1679938833"
                },
                "os": [{
                    "osfingerprint": [{
                        "item": {
                            "fingerprint": "OS:SCAN(V=7.91%E=4%D=3/27%OT=21%CT=1%CU=34612%PV=Y%DS=0%DC=L%G=Y%TM=6421D53\nOS:E%P=i686-pc-windows-windows)SEQ(SP=F9%GCD=1%ISR=109%CI=I%II=I%TS=U)SEQ(S\nOS:P=F9%GCD=1%ISR=109%TI=I%CI=I%II=I%TS=U)OPS(O1=MFFD7NW8NNS%O2=MFFD7NW8NNS\nOS:%O3=MFFD7NW8%O4=MFFD7NW8NNS%O5=MFFD7NW8NNS%O6=MFFD7NNS)WIN(W1=FFFF%W2=FF\nOS:FF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=MFFD7NW8NN\nOS:S%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=\nOS:Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=\nOS:Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=A\nOS:R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=8\nOS:0%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=\nOS:G%RIPCK=Z%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)\n"
                        }
                    }
                    ],
                    "osmatch": [{
                        "item": {
                            "accuracy": "99",
                            "line": "69956",
                            "name": "Microsoft Windows 10 1809 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "99",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "95",
                            "line": "69915",
                            "name": "Microsoft Windows 10 1709 - 1803"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "95",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "93",
                            "line": "69751",
                            "name": "Microsoft Windows 10 1607"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10:1607"],
                            "item": {
                                "accuracy": "93",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "93",
                            "line": "69936",
                            "name": "Microsoft Windows 10 1709 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "93",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "92",
                            "line": "69805",
                            "name": "Microsoft Windows 10 1703"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10:1703"],
                            "item": {
                                "accuracy": "92",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "92",
                            "line": "77640",
                            "name": "Microsoft Windows 7 SP1"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_7::sp1"],
                            "item": {
                                "accuracy": "92",
                                "osfamily": "Windows",
                                "osgen": "7",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "91",
                            "line": "78822",
                            "name": "Microsoft Windows Longhorn"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "Longhorn",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "91",
                            "line": "76914",
                            "name": "Microsoft Windows 7 or 8.1 R1"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_7"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "7",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }, {
                            "cpe": ["cpe:/o:microsoft:windows_8.1:r1"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "8.1",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "90",
                            "line": "69419",
                            "name": "Microsoft Windows 10 10586 - 14393"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "90",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "90",
                            "line": "69516",
                            "name": "Microsoft Windows 10 1511"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10:1511"],
                            "item": {
                                "accuracy": "90",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }
                    ],
                    "portused": [{
                        "item": {
                            "portid": "21",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }, {
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "34612",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1016",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1016",
                            "state": "closed"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "21",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "ftp",
                                "servicefp": "SF-Port21-TCP:V=7.91%I=7%D=3/27%Time=6421D518%P=i686-pc-windows-windows%r(NULL,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(GenericLines,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(Help,17C,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n214-The\\x20following\\x20commands\\x20are\\x20recognized\\.\\r\\n\\x20NOP\\x20\\x20USER\\x20TYPE\\x20SYST\\x20SIZE\\x20RNTO\\x20RNFR\\x20RMD\\x20\\x20REST\\x20QUIT\\r\\n\\x20HELP\\x20XMKD\\x20MLST\\x20MKD\\x20\\x20EPSV\\x20XCWD\\x20NOOP\\x20AUTH\\x20OPTS\\x20DELE\\r\\n\\x20CWD\\x20\\x20CDUP\\x20APPE\\x20STOR\\x20ALLO\\x20RETR\\x20PWD\\x20\\x20FEAT\\x20CLNT\\x20MFMT\\r\\n\\x20MODE\\x20XRMD\\x20PROT\\x20ADAT\\x20ABOR\\x20XPWD\\x20MDTM\\x20LIST\\x20MLSD\\x20PBSZ\\r\\n\\x20NLST\\x20EPRT\\x20PASS\\x20STRU\\x20PASV\\x20STAT\\x20PORT\\r\\n214\\x20Help\\x20ok\\.\\r\\n\")%r(GetRequest,76,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n501\\x20What\\x20are\\x20you\\x20trying\\x20to\\x20do\\?\\x20Go\\x20away\\.\\r\\n\")%r(HTTPOptions,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RTSPRequest,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RPCCheck,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSVersionBindReqTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSStatusRequestTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(SSLSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TerminalServerCookie,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TLSSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\");"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "80",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:microsoft:internet_information_server:10.0", "cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "http",
                                "ostype": "Windows",
                                "product": "Microsoft IIS httpd",
                                "version": "10.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "135",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "msrpc",
                                "ostype": "Windows",
                                "product": "Microsoft Windows RPC"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "137",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "netbios-ns"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "no-response",
                                "reason_ttl": "0",
                                "state": "filtered"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "139",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "netbios-ssn",
                                "ostype": "Windows",
                                "product": "Microsoft Windows netbios-ssn"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "445",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "microsoft-ds"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "903",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "tunnel": "ssl",
                                "version": "1.10"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "913",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "version": "1.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "localhost-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "250",
                        "values": "535F53E8,8D6B1BB7,ACE9E18B,E3DB80CB,AC7CDBE9,6389F125"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "none returned (unsupported)"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "0",
                        "srtt": "0",
                        "to": "100000"
                    }
                }
                ]
            }, {
                "address": [{
                    "item": {
                        "addr": "192.168.1.103",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "F0:9F:C2:62:52:11",
                        "addrtype": "mac",
                        "vendor": "Ubiquiti Networks"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "item": {
                    "endtime": "1679939001",
                    "starttime": "1679938833"
                },
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ]
            }
            ],
            "hosthint": [{
                "address": [{
                    "item": {
                        "addr": "192.168.1.103",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "F0:9F:C2:62:52:11",
                        "addrtype": "mac",
                        "vendor": "Ubiquiti Networks"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ]
            }
            ],
            "item": {
                "args": "nmap --host-timeout=120s -T4 -sV -O -oX - -p1-1024  192.168.1.103",
                "scanner": "nmap",
                "start": "1679938832",
                "startstr": "Mon Mar 27 10:40:32 2023",
                "version": "7.91",
                "xmloutputversion": "1.05"
            },
            "runstats": [{
                "finished": [{
                    "item": {
                        "elapsed": "169.85",
                        "exit": "success",
                        "summary": "Nmap done at Mon Mar 27 10:43:21 2023; 2 IP addresses (2 hosts up) scanned in 169.85 seconds",
                        "time": "1679939001",
                        "timestr": "Mon Mar 27 10:43:21 2023"
                    }
                }
                ],
                "hosts": [{
                    "item": {
                        "down": "0",
                        "total": "2",
                        "up": "2"
                    }
                }
                ]
            }
            ],
            "scaninfo": [{
                "item": {
                    "numservices": "1024",
                    "protocol": "tcp",
                    "services": "1-1024",
                    "type": "syn"
                }
            }
            ],
            "verbose": [{
                "item": {
                    "level": "0"
                }
            }
            ]
        },
        "192.168.1.104": {
            "debugging": [{
                "item": {
                    "level": "0"
                }
            }
            ],
            "host": [{
                "address": [{
                    "item": {
                        "addr": "172.30.160.1",
                        "addrtype": "ipv4"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "0"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "Incremental",
                        "values": "76D,773,779,77F,785,78B"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938878",
                    "starttime": "1679938833"
                },
                "os": [{
                    "osfingerprint": [{
                        "item": {
                            "fingerprint": "OS:SCAN(V=7.91%E=4%D=3/27%OT=21%CT=1%CU=41351%PV=Y%DS=0%DC=L%G=Y%TM=6421D53\nOS:E%P=i686-pc-windows-windows)SEQ(SP=FE%GCD=1%ISR=106%CI=I%II=I%TS=U)SEQ(S\nOS:P=FE%GCD=1%ISR=106%TI=I%CI=I%II=I%SS=S%TS=U)OPS(O1=MFFD7NW8NNS%O2=MFFD7N\nOS:W8NNS%O3=MFFD7NW8%O4=MFFD7NW8NNS%O5=MFFD7NW8NNS%O6=MFFD7NNS)WIN(W1=FFFF%\nOS:W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=MFFD7\nOS:NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W\nOS:=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)\nOS:T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S\nOS:+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=\nOS:Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G\nOS:%RID=G%RIPCK=Z%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)\n"
                        }
                    }
                    ],
                    "osmatch": [{
                        "item": {
                            "accuracy": "99",
                            "line": "69956",
                            "name": "Microsoft Windows 10 1809 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "99",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "95",
                            "line": "69915",
                            "name": "Microsoft Windows 10 1709 - 1803"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "95",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "93",
                            "line": "69751",
                            "name": "Microsoft Windows 10 1607"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10:1607"],
                            "item": {
                                "accuracy": "93",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "93",
                            "line": "69897",
                            "name": "Microsoft Windows 10 1703"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10:1703"],
                            "item": {
                                "accuracy": "93",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "92",
                            "line": "77640",
                            "name": "Microsoft Windows 7 SP1"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_7::sp1"],
                            "item": {
                                "accuracy": "92",
                                "osfamily": "Windows",
                                "osgen": "7",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "92",
                            "line": "69936",
                            "name": "Microsoft Windows 10 1709 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "92",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "91",
                            "line": "78822",
                            "name": "Microsoft Windows Longhorn"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "Longhorn",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "91",
                            "line": "76914",
                            "name": "Microsoft Windows 7 or 8.1 R1"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_7"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "7",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }, {
                            "cpe": ["cpe:/o:microsoft:windows_8.1:r1"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "8.1",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "91",
                            "line": "69419",
                            "name": "Microsoft Windows 10 10586 - 14393"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "91",
                            "line": "78072",
                            "name": "Microsoft Windows 7 or 8.1 R1 or Server 2008 R2 SP1"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_8.1:r1"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "8.1",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }, {
                            "cpe": ["cpe:/o:microsoft:windows_7"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "7",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }, {
                            "cpe": ["cpe:/o:microsoft:windows_server_2008:r2"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "2008",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }
                    ],
                    "portused": [{
                        "item": {
                            "portid": "21",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }, {
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "41351",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1016",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1016",
                            "state": "closed"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "21",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "ftp",
                                "servicefp": "SF-Port21-TCP:V=7.91%I=7%D=3/27%Time=6421D518%P=i686-pc-windows-windows%r(NULL,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(GenericLines,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(Help,17C,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n214-The\\x20following\\x20commands\\x20are\\x20recognized\\.\\r\\n\\x20NOP\\x20\\x20USER\\x20TYPE\\x20SYST\\x20SIZE\\x20RNTO\\x20RNFR\\x20RMD\\x20\\x20REST\\x20QUIT\\r\\n\\x20HELP\\x20XMKD\\x20MLST\\x20MKD\\x20\\x20EPSV\\x20XCWD\\x20NOOP\\x20AUTH\\x20OPTS\\x20DELE\\r\\n\\x20CWD\\x20\\x20CDUP\\x20APPE\\x20STOR\\x20ALLO\\x20RETR\\x20PWD\\x20\\x20FEAT\\x20CLNT\\x20MFMT\\r\\n\\x20MODE\\x20XRMD\\x20PROT\\x20ADAT\\x20ABOR\\x20XPWD\\x20MDTM\\x20LIST\\x20MLSD\\x20PBSZ\\r\\n\\x20NLST\\x20EPRT\\x20PASS\\x20STRU\\x20PASV\\x20STAT\\x20PORT\\r\\n214\\x20Help\\x20ok\\.\\r\\n\")%r(GetRequest,76,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n501\\x20What\\x20are\\x20you\\x20trying\\x20to\\x20do\\?\\x20Go\\x20away\\.\\r\\n\")%r(HTTPOptions,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RTSPRequest,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RPCCheck,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSVersionBindReqTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSStatusRequestTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(SSLSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TerminalServerCookie,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TLSSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\");"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "80",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:microsoft:internet_information_server:10.0", "cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "http",
                                "ostype": "Windows",
                                "product": "Microsoft IIS httpd",
                                "version": "10.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "135",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "msrpc",
                                "ostype": "Windows",
                                "product": "Microsoft Windows RPC"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "137",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "netbios-ns"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "no-response",
                                "reason_ttl": "0",
                                "state": "filtered"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "139",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "netbios-ssn",
                                "ostype": "Windows",
                                "product": "Microsoft Windows netbios-ssn"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "445",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "microsoft-ds"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "903",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "tunnel": "ssl",
                                "version": "1.10"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "913",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "version": "1.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "localhost-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "254",
                        "values": "3D78CA72,715AA4CF,9F1C6638,D1398ED8,CA9E9C54,C056A6A"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "none returned (unsupported)"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "0",
                        "srtt": "0",
                        "to": "100000"
                    }
                }
                ]
            }, {
                "address": [{
                    "item": {
                        "addr": "192.168.1.104",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "78:8A:20:89:AA:F1",
                        "addrtype": "mac",
                        "vendor": "Ubiquiti Networks"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "1"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "All zeros",
                        "values": "0,0,0,0,0,0"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938880",
                    "starttime": "1679938833"
                },
                "os": [{
                    "osmatch": [{
                        "item": {
                            "accuracy": "100",
                            "line": "66947",
                            "name": "OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1 or 4.4)"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:linux:linux_kernel:3.18"],
                            "item": {
                                "accuracy": "100",
                                "osfamily": "Linux",
                                "osgen": "3.X",
                                "type": "WAP",
                                "vendor": "Linux"
                            }
                        }, {
                            "cpe": ["cpe:/o:linux:linux_kernel:4.1"],
                            "item": {
                                "accuracy": "100",
                                "osfamily": "Linux",
                                "osgen": "4.X",
                                "type": "WAP",
                                "vendor": "Linux"
                            }
                        }
                        ]
                    }
                    ],
                    "portused": [{
                        "item": {
                            "portid": "22",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }, {
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "33960",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1023",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1023",
                            "state": "closed"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "22",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:matt_johnston:dropbear_ssh_server", "cpe:/o:linux:linux_kernel"],
                            "item": {
                                "conf": "10",
                                "extrainfo": "protocol 2.0",
                                "method": "probed",
                                "name": "ssh",
                                "ostype": "Linux",
                                "product": "Dropbear sshd"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "64",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "255",
                        "values": "74BB0480,6A5948A8,7F0E3C4B,7831D5DD,BCFF0646,D0C9263F"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "100HZ",
                        "values": "23D9652,23D965C,23D9666,23D9670,23D967A,23D9685"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "1065",
                        "srtt": "2278",
                        "to": "100000"
                    }
                }
                ],
                "uptime": [{
                    "item": {
                        "lastboot": "Thu Mar 23 02:16:13 2023",
                        "seconds": "375907"
                    }
                }
                ]
            }
            ],
            "hosthint": [{
                "address": [{
                    "item": {
                        "addr": "192.168.1.104",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "78:8A:20:89:AA:F1",
                        "addrtype": "mac",
                        "vendor": "Ubiquiti Networks"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ]
            }
            ],
            "item": {
                "args": "nmap --host-timeout=120s -T4 -sV -O -oX - -p1-1024  192.168.1.104",
                "scanner": "nmap",
                "start": "1679938832",
                "startstr": "Mon Mar 27 10:40:32 2023",
                "version": "7.91",
                "xmloutputversion": "1.05"
            },
            "runstats": [{
                "finished": [{
                    "item": {
                        "elapsed": "48.60",
                        "exit": "success",
                        "summary": "Nmap done at Mon Mar 27 10:41:20 2023; 2 IP addresses (2 hosts up) scanned in 48.60 seconds",
                        "time": "1679938880",
                        "timestr": "Mon Mar 27 10:41:20 2023"
                    }
                }
                ],
                "hosts": [{
                    "item": {
                        "down": "0",
                        "total": "2",
                        "up": "2"
                    }
                }
                ]
            }
            ],
            "scaninfo": [{
                "item": {
                    "numservices": "1024",
                    "protocol": "tcp",
                    "services": "1-1024",
                    "type": "syn"
                }
            }
            ],
            "verbose": [{
                "item": {
                    "level": "0"
                }
            }
            ]
        },
        "192.168.1.11": {
            "debugging": [{
                "item": {
                    "level": "0"
                }
            }
            ],
            "host": [{
                "address": [{
                    "item": {
                        "addr": "172.30.160.1",
                        "addrtype": "ipv4"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "0"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "Busy server or unknown class",
                        "values": "37E,3BB,3C9,3D7,3E5,3F3"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938869",
                    "starttime": "1679938833"
                },
                "os": [{
                    "osmatch": [{
                        "item": {
                            "accuracy": "100",
                            "line": "69956",
                            "name": "Microsoft Windows 10 1809 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "100",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }
                    ],
                    "portused": [{
                        "item": {
                            "portid": "21",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }, {
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "32226",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1016",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1016",
                            "state": "closed"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "21",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "ftp",
                                "servicefp": "SF-Port21-TCP:V=7.91%I=7%D=3/27%Time=6421D518%P=i686-pc-windows-windows%r(NULL,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(GenericLines,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(Help,17C,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n214-The\\x20following\\x20commands\\x20are\\x20recognized\\.\\r\\n\\x20NOP\\x20\\x20USER\\x20TYPE\\x20SYST\\x20SIZE\\x20RNTO\\x20RNFR\\x20RMD\\x20\\x20REST\\x20QUIT\\r\\n\\x20HELP\\x20XMKD\\x20MLST\\x20MKD\\x20\\x20EPSV\\x20XCWD\\x20NOOP\\x20AUTH\\x20OPTS\\x20DELE\\r\\n\\x20CWD\\x20\\x20CDUP\\x20APPE\\x20STOR\\x20ALLO\\x20RETR\\x20PWD\\x20\\x20FEAT\\x20CLNT\\x20MFMT\\r\\n\\x20MODE\\x20XRMD\\x20PROT\\x20ADAT\\x20ABOR\\x20XPWD\\x20MDTM\\x20LIST\\x20MLSD\\x20PBSZ\\r\\n\\x20NLST\\x20EPRT\\x20PASS\\x20STRU\\x20PASV\\x20STAT\\x20PORT\\r\\n214\\x20Help\\x20ok\\.\\r\\n\")%r(GetRequest,76,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n501\\x20What\\x20are\\x20you\\x20trying\\x20to\\x20do\\?\\x20Go\\x20away\\.\\r\\n\")%r(HTTPOptions,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RTSPRequest,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RPCCheck,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSVersionBindReqTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSStatusRequestTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(SSLSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TerminalServerCookie,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TLSSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\");"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "80",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:microsoft:internet_information_server:10.0", "cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "http",
                                "ostype": "Windows",
                                "product": "Microsoft IIS httpd",
                                "version": "10.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "135",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "msrpc",
                                "ostype": "Windows",
                                "product": "Microsoft Windows RPC"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "137",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "netbios-ns"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "no-response",
                                "reason_ttl": "0",
                                "state": "filtered"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "139",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "netbios-ssn",
                                "ostype": "Windows",
                                "product": "Microsoft Windows netbios-ssn"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "445",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "microsoft-ds"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "903",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "tunnel": "ssl",
                                "version": "1.10"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "913",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "version": "1.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "localhost-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "265",
                        "values": "3489C3E,58BB6FF3,5B4D85BB,55234515,41531960,BFBC8BE5"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "none returned (unsupported)"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "317",
                        "srtt": "171",
                        "to": "100000"
                    }
                }
                ]
            }, {
                "address": [{
                    "item": {
                        "addr": "192.168.1.11",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "00:15:5D:01:45:00",
                        "addrtype": "mac",
                        "vendor": "Microsoft"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "1"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "item": {
                    "endtime": "1679938893",
                    "starttime": "1679938833"
                },
                "os": [""],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1024",
                                "reason": "no-responses"
                            }
                        }
                        ],
                        "item": {
                            "count": "1024",
                            "state": "filtered"
                        }
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "2120",
                        "srtt": "1585",
                        "to": "100000"
                    }
                }
                ]
            }
            ],
            "hosthint": [{
                "address": [{
                    "item": {
                        "addr": "192.168.1.11",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "00:15:5D:01:45:00",
                        "addrtype": "mac",
                        "vendor": "Microsoft"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ]
            }
            ],
            "item": {
                "args": "nmap --host-timeout=120s -T4 -sV -O -oX - -p1-1024  192.168.1.11",
                "scanner": "nmap",
                "start": "1679938832",
                "startstr": "Mon Mar 27 10:40:32 2023",
                "version": "7.91",
                "xmloutputversion": "1.05"
            },
            "runstats": [{
                "finished": [{
                    "item": {
                        "elapsed": "61.91",
                        "exit": "success",
                        "summary": "Nmap done at Mon Mar 27 10:41:33 2023; 2 IP addresses (2 hosts up) scanned in 61.91 seconds",
                        "time": "1679938893",
                        "timestr": "Mon Mar 27 10:41:33 2023"
                    }
                }
                ],
                "hosts": [{
                    "item": {
                        "down": "0",
                        "total": "2",
                        "up": "2"
                    }
                }
                ]
            }
            ],
            "scaninfo": [{
                "item": {
                    "numservices": "1024",
                    "protocol": "tcp",
                    "services": "1-1024",
                    "type": "syn"
                }
            }
            ],
            "verbose": [{
                "item": {
                    "level": "0"
                }
            }
            ]
        },
        "192.168.1.111": {
            "debugging": [{
                "item": {
                    "level": "0"
                }
            }
            ],
            "host": [{
                "address": [{
                    "item": {
                        "addr": "172.30.160.1",
                        "addrtype": "ipv4"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "0"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "Busy server or unknown class",
                        "values": "3C5,3D3,3E1,3EF,3FF,41F"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938869",
                    "starttime": "1679938833"
                },
                "os": [{
                    "osmatch": [{
                        "item": {
                            "accuracy": "100",
                            "line": "69956",
                            "name": "Microsoft Windows 10 1809 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "100",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }
                    ],
                    "portused": [{
                        "item": {
                            "portid": "21",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }, {
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "35372",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1016",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1016",
                            "state": "closed"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "21",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "ftp",
                                "servicefp": "SF-Port21-TCP:V=7.91%I=7%D=3/27%Time=6421D518%P=i686-pc-windows-windows%r(NULL,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(GenericLines,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(Help,17C,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n214-The\\x20following\\x20commands\\x20are\\x20recognized\\.\\r\\n\\x20NOP\\x20\\x20USER\\x20TYPE\\x20SYST\\x20SIZE\\x20RNTO\\x20RNFR\\x20RMD\\x20\\x20REST\\x20QUIT\\r\\n\\x20HELP\\x20XMKD\\x20MLST\\x20MKD\\x20\\x20EPSV\\x20XCWD\\x20NOOP\\x20AUTH\\x20OPTS\\x20DELE\\r\\n\\x20CWD\\x20\\x20CDUP\\x20APPE\\x20STOR\\x20ALLO\\x20RETR\\x20PWD\\x20\\x20FEAT\\x20CLNT\\x20MFMT\\r\\n\\x20MODE\\x20XRMD\\x20PROT\\x20ADAT\\x20ABOR\\x20XPWD\\x20MDTM\\x20LIST\\x20MLSD\\x20PBSZ\\r\\n\\x20NLST\\x20EPRT\\x20PASS\\x20STRU\\x20PASV\\x20STAT\\x20PORT\\r\\n214\\x20Help\\x20ok\\.\\r\\n\")%r(GetRequest,76,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n501\\x20What\\x20are\\x20you\\x20trying\\x20to\\x20do\\?\\x20Go\\x20away\\.\\r\\n\")%r(HTTPOptions,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RTSPRequest,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RPCCheck,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSVersionBindReqTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSStatusRequestTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(SSLSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TerminalServerCookie,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TLSSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\");"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "80",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:microsoft:internet_information_server:10.0", "cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "http",
                                "ostype": "Windows",
                                "product": "Microsoft IIS httpd",
                                "version": "10.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "135",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "msrpc",
                                "ostype": "Windows",
                                "product": "Microsoft Windows RPC"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "137",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "netbios-ns"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "no-response",
                                "reason_ttl": "0",
                                "state": "filtered"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "139",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "netbios-ssn",
                                "ostype": "Windows",
                                "product": "Microsoft Windows netbios-ssn"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "445",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "microsoft-ds"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "903",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "tunnel": "ssl",
                                "version": "1.10"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "913",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "version": "1.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "localhost-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "263",
                        "values": "28CD01D5,6CEB1452,B675FE30,A7334D05,21A97042,1A51E921"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "none returned (unsupported)"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "263",
                        "srtt": "142",
                        "to": "100000"
                    }
                }
                ]
            }, {
                "address": [{
                    "item": {
                        "addr": "192.168.1.111",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "F0:A3:B2:78:CF:2B",
                        "addrtype": "mac"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "1"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "item": {
                    "endtime": "1679938872",
                    "starttime": "1679938833"
                },
                "os": [{
                    "portused": [{
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "42139",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1024",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1024",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "2313",
                        "srtt": "3596",
                        "to": "100000"
                    }
                }
                ]
            }
            ],
            "hosthint": [{
                "address": [{
                    "item": {
                        "addr": "192.168.1.111",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "F0:A3:B2:78:CF:2B",
                        "addrtype": "mac"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ]
            }
            ],
            "item": {
                "args": "nmap --host-timeout=120s -T4 -sV -O -oX - -p1-1024  192.168.1.111",
                "scanner": "nmap",
                "start": "1679938832",
                "startstr": "Mon Mar 27 10:40:32 2023",
                "version": "7.91",
                "xmloutputversion": "1.05"
            },
            "runstats": [{
                "finished": [{
                    "item": {
                        "elapsed": "40.40",
                        "exit": "success",
                        "summary": "Nmap done at Mon Mar 27 10:41:12 2023; 2 IP addresses (2 hosts up) scanned in 40.40 seconds",
                        "time": "1679938872",
                        "timestr": "Mon Mar 27 10:41:12 2023"
                    }
                }
                ],
                "hosts": [{
                    "item": {
                        "down": "0",
                        "total": "2",
                        "up": "2"
                    }
                }
                ]
            }
            ],
            "scaninfo": [{
                "item": {
                    "numservices": "1024",
                    "protocol": "tcp",
                    "services": "1-1024",
                    "type": "syn"
                }
            }
            ],
            "verbose": [{
                "item": {
                    "level": "0"
                }
            }
            ]
        },
        "192.168.1.13": {
            "debugging": [{
                "item": {
                    "level": "0"
                }
            }
            ],
            "host": [{
                "address": [{
                    "item": {
                        "addr": "172.30.160.1",
                        "addrtype": "ipv4"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "0"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "Incremental",
                        "values": "76F,775,77B,781,787,78D"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938878",
                    "starttime": "1679938833"
                },
                "os": [{
                    "osfingerprint": [{
                        "item": {
                            "fingerprint": "OS:SCAN(V=7.91%E=4%D=3/27%OT=21%CT=1%CU=31057%PV=Y%DS=0%DC=L%G=Y%TM=6421D53\nOS:E%P=i686-pc-windows-windows)SEQ(SP=FE%GCD=1%ISR=10E%CI=I%II=I%TS=U)SEQ(S\nOS:P=FE%GCD=1%ISR=10E%TI=I%CI=I%II=I%TS=U)OPS(O1=MFFD7NW8NNS%O2=MFFD7NW8NNS\nOS:%O3=MFFD7NW8%O4=MFFD7NW8NNS%O5=MFFD7NW8NNS%O6=MFFD7NNS)WIN(W1=FFFF%W2=FF\nOS:FF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=MFFD7NW8NN\nOS:S%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=\nOS:Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=\nOS:Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=A\nOS:R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=8\nOS:0%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=\nOS:G%RIPCK=Z%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)\n"
                        }
                    }
                    ],
                    "osmatch": [{
                        "item": {
                            "accuracy": "99",
                            "line": "69956",
                            "name": "Microsoft Windows 10 1809 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "99",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "95",
                            "line": "69915",
                            "name": "Microsoft Windows 10 1709 - 1803"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "95",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "93",
                            "line": "69751",
                            "name": "Microsoft Windows 10 1607"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10:1607"],
                            "item": {
                                "accuracy": "93",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "93",
                            "line": "69897",
                            "name": "Microsoft Windows 10 1703"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10:1703"],
                            "item": {
                                "accuracy": "93",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "93",
                            "line": "69936",
                            "name": "Microsoft Windows 10 1709 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "93",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "92",
                            "line": "77640",
                            "name": "Microsoft Windows 7 SP1"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_7::sp1"],
                            "item": {
                                "accuracy": "92",
                                "osfamily": "Windows",
                                "osgen": "7",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "92",
                            "line": "78822",
                            "name": "Microsoft Windows Longhorn"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "accuracy": "92",
                                "osfamily": "Windows",
                                "osgen": "Longhorn",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "91",
                            "line": "69516",
                            "name": "Microsoft Windows 10 1511"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10:1511"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "91",
                            "line": "76914",
                            "name": "Microsoft Windows 7 or 8.1 R1"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_7"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "7",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }, {
                            "cpe": ["cpe:/o:microsoft:windows_8.1:r1"],
                            "item": {
                                "accuracy": "91",
                                "osfamily": "Windows",
                                "osgen": "8.1",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "accuracy": "90",
                            "line": "69325",
                            "name": "Microsoft Windows 10"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "90",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }
                    ],
                    "portused": [{
                        "item": {
                            "portid": "21",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }, {
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "31057",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1016",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1016",
                            "state": "closed"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "21",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "ftp",
                                "servicefp": "SF-Port21-TCP:V=7.91%I=7%D=3/27%Time=6421D518%P=i686-pc-windows-windows%r(NULL,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(GenericLines,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(Help,17C,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n214-The\\x20following\\x20commands\\x20are\\x20recognized\\.\\r\\n\\x20NOP\\x20\\x20USER\\x20TYPE\\x20SYST\\x20SIZE\\x20RNTO\\x20RNFR\\x20RMD\\x20\\x20REST\\x20QUIT\\r\\n\\x20HELP\\x20XMKD\\x20MLST\\x20MKD\\x20\\x20EPSV\\x20XCWD\\x20NOOP\\x20AUTH\\x20OPTS\\x20DELE\\r\\n\\x20CWD\\x20\\x20CDUP\\x20APPE\\x20STOR\\x20ALLO\\x20RETR\\x20PWD\\x20\\x20FEAT\\x20CLNT\\x20MFMT\\r\\n\\x20MODE\\x20XRMD\\x20PROT\\x20ADAT\\x20ABOR\\x20XPWD\\x20MDTM\\x20LIST\\x20MLSD\\x20PBSZ\\r\\n\\x20NLST\\x20EPRT\\x20PASS\\x20STRU\\x20PASV\\x20STAT\\x20PORT\\r\\n214\\x20Help\\x20ok\\.\\r\\n\")%r(GetRequest,76,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n501\\x20What\\x20are\\x20you\\x20trying\\x20to\\x20do\\?\\x20Go\\x20away\\.\\r\\n\")%r(HTTPOptions,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RTSPRequest,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RPCCheck,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSVersionBindReqTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSStatusRequestTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(SSLSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TerminalServerCookie,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TLSSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\");"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "80",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:microsoft:internet_information_server:10.0", "cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "http",
                                "ostype": "Windows",
                                "product": "Microsoft IIS httpd",
                                "version": "10.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "135",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "msrpc",
                                "ostype": "Windows",
                                "product": "Microsoft Windows RPC"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "137",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "netbios-ns"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "no-response",
                                "reason_ttl": "0",
                                "state": "filtered"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "139",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "netbios-ssn",
                                "ostype": "Windows",
                                "product": "Microsoft Windows netbios-ssn"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "445",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "microsoft-ds"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "903",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "tunnel": "ssl",
                                "version": "1.10"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "913",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "version": "1.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "localhost-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "255",
                        "values": "10530663,C432E2E2,5ABFA42E,BAA44835,519D010B,1C6397FE"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "none returned (unsupported)"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "110",
                        "srtt": "55",
                        "to": "100000"
                    }
                }
                ]
            }, {
                "address": [{
                    "item": {
                        "addr": "192.168.1.13",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "00:15:5D:01:45:04",
                        "addrtype": "mac",
                        "vendor": "Microsoft"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "1"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "All zeros",
                        "values": "0,0,0,0,0,0"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938886",
                    "starttime": "1679938833"
                },
                "os": [{
                    "osmatch": [{
                        "item": {
                            "accuracy": "100",
                            "line": "67241",
                            "name": "Linux 4.15 - 5.6"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:linux:linux_kernel:4"],
                            "item": {
                                "accuracy": "100",
                                "osfamily": "Linux",
                                "osgen": "4.X",
                                "type": "general purpose",
                                "vendor": "Linux"
                            }
                        }, {
                            "cpe": ["cpe:/o:linux:linux_kernel:5"],
                            "item": {
                                "accuracy": "100",
                                "osfamily": "Linux",
                                "osgen": "5.X",
                                "type": "general purpose",
                                "vendor": "Linux"
                            }
                        }
                        ]
                    }
                    ],
                    "portused": [{
                        "item": {
                            "portid": "22",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }, {
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "34080",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1022",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1022",
                            "state": "closed"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "22",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:openbsd:openssh:8.2p1", "cpe:/o:linux:linux_kernel"],
                            "item": {
                                "conf": "10",
                                "extrainfo": "Ubuntu Linux; protocol 2.0",
                                "method": "probed",
                                "name": "ssh",
                                "ostype": "Linux",
                                "product": "OpenSSH",
                                "version": "8.2p1 Ubuntu 4ubuntu0.5"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "64",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "80",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:igor_sysoev:nginx:1.18.0", "cpe:/o:linux:linux_kernel"],
                            "item": {
                                "conf": "10",
                                "extrainfo": "Ubuntu",
                                "method": "probed",
                                "name": "http",
                                "ostype": "Linux",
                                "product": "nginx",
                                "version": "1.18.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "64",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "260",
                        "values": "D09E0A81,33E588E1,F12DF1D1,CA8ACAD1,D36CC81E,208AF4EE"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "1000HZ",
                        "values": "437D8A08,437D8A6C,437D8AD1,437D8B37,437D8B9C,437D8C01"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "1022",
                        "srtt": "1750",
                        "to": "100000"
                    }
                }
                ],
                "uptime": [{
                    "item": {
                        "lastboot": "Tue Mar 14 08:09:45 2023",
                        "seconds": "1132301"
                    }
                }
                ]
            }
            ],
            "hosthint": [{
                "address": [{
                    "item": {
                        "addr": "192.168.1.13",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "00:15:5D:01:45:04",
                        "addrtype": "mac",
                        "vendor": "Microsoft"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ]
            }
            ],
            "item": {
                "args": "nmap --host-timeout=120s -T4 -sV -O -oX - -p1-1024  192.168.1.13",
                "scanner": "nmap",
                "start": "1679938832",
                "startstr": "Mon Mar 27 10:40:32 2023",
                "version": "7.91",
                "xmloutputversion": "1.05"
            },
            "runstats": [{
                "finished": [{
                    "item": {
                        "elapsed": "54.76",
                        "exit": "success",
                        "summary": "Nmap done at Mon Mar 27 10:41:26 2023; 2 IP addresses (2 hosts up) scanned in 54.76 seconds",
                        "time": "1679938886",
                        "timestr": "Mon Mar 27 10:41:26 2023"
                    }
                }
                ],
                "hosts": [{
                    "item": {
                        "down": "0",
                        "total": "2",
                        "up": "2"
                    }
                }
                ]
            }
            ],
            "scaninfo": [{
                "item": {
                    "numservices": "1024",
                    "protocol": "tcp",
                    "services": "1-1024",
                    "type": "syn"
                }
            }
            ],
            "verbose": [{
                "item": {
                    "level": "0"
                }
            }
            ]
        },
        "192.168.1.139": {
            "debugging": [{
                "item": {
                    "level": "0"
                }
            }
            ],
            "host": [{
                "address": [{
                    "item": {
                        "addr": "172.30.160.1",
                        "addrtype": "ipv4"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "0"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "Incremental",
                        "values": "62D,62F,631,633,635,639"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938871",
                    "starttime": "1679938834"
                },
                "os": [{
                    "osmatch": [{
                        "item": {
                            "accuracy": "100",
                            "line": "69956",
                            "name": "Microsoft Windows 10 1809 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "100",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }
                    ],
                    "portused": [{
                        "item": {
                            "portid": "21",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }, {
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "31335",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1016",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1016",
                            "state": "closed"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "21",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "ftp",
                                "servicefp": "SF-Port21-TCP:V=7.91%I=7%D=3/27%Time=6421D51A%P=i686-pc-windows-windows%r(NULL,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(GenericLines,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(Help,17C,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n214-The\\x20following\\x20commands\\x20are\\x20recognized\\.\\r\\n\\x20NOP\\x20\\x20USER\\x20TYPE\\x20SYST\\x20SIZE\\x20RNTO\\x20RNFR\\x20RMD\\x20\\x20REST\\x20QUIT\\r\\n\\x20HELP\\x20XMKD\\x20MLST\\x20MKD\\x20\\x20EPSV\\x20XCWD\\x20NOOP\\x20AUTH\\x20OPTS\\x20DELE\\r\\n\\x20CWD\\x20\\x20CDUP\\x20APPE\\x20STOR\\x20ALLO\\x20RETR\\x20PWD\\x20\\x20FEAT\\x20CLNT\\x20MFMT\\r\\n\\x20MODE\\x20XRMD\\x20PROT\\x20ADAT\\x20ABOR\\x20XPWD\\x20MDTM\\x20LIST\\x20MLSD\\x20PBSZ\\r\\n\\x20NLST\\x20EPRT\\x20PASS\\x20STRU\\x20PASV\\x20STAT\\x20PORT\\r\\n214\\x20Help\\x20ok\\.\\r\\n\")%r(GetRequest,76,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n501\\x20What\\x20are\\x20you\\x20trying\\x20to\\x20do\\?\\x20Go\\x20away\\.\\r\\n\")%r(HTTPOptions,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RTSPRequest,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RPCCheck,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSVersionBindReqTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSStatusRequestTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(SSLSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TerminalServerCookie,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TLSSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\");"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "80",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:microsoft:internet_information_server:10.0", "cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "http",
                                "ostype": "Windows",
                                "product": "Microsoft IIS httpd",
                                "version": "10.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "135",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "msrpc",
                                "ostype": "Windows",
                                "product": "Microsoft Windows RPC"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "137",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "netbios-ns"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "no-response",
                                "reason_ttl": "0",
                                "state": "filtered"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "139",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "netbios-ssn",
                                "ostype": "Windows",
                                "product": "Microsoft Windows netbios-ssn"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "445",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "microsoft-ds"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "903",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "tunnel": "ssl",
                                "version": "1.10"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "913",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "version": "1.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "localhost-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "264",
                        "values": "DD6132A3,C59FC554,2A329186,A0BFADF5,A278747B,C2E583FC"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "none returned (unsupported)"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "39070",
                        "srtt": "43121",
                        "to": "199401"
                    }
                }
                ]
            }, {
                "address": [{
                    "item": {
                        "addr": "192.168.1.139",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "6A:0A:B5:8A:D1:DB",
                        "addrtype": "mac"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "1"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "item": {
                    "endtime": "1679938899",
                    "starttime": "1679938833"
                },
                "os": [{
                    "portused": [{
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "41103",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1024",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1024",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "27034",
                        "srtt": "36613",
                        "to": "144749"
                    }
                }
                ]
            }
            ],
            "hosthint": [{
                "address": [{
                    "item": {
                        "addr": "192.168.1.139",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "6A:0A:B5:8A:D1:DB",
                        "addrtype": "mac"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ]
            }
            ],
            "item": {
                "args": "nmap --host-timeout=120s -T4 -sV -O -oX - -p1-1024  192.168.1.139",
                "scanner": "nmap",
                "start": "1679938832",
                "startstr": "Mon Mar 27 10:40:32 2023",
                "version": "7.91",
                "xmloutputversion": "1.05"
            },
            "runstats": [{
                "finished": [{
                    "item": {
                        "elapsed": "67.19",
                        "exit": "success",
                        "summary": "Nmap done at Mon Mar 27 10:41:39 2023; 2 IP addresses (2 hosts up) scanned in 67.19 seconds",
                        "time": "1679938899",
                        "timestr": "Mon Mar 27 10:41:39 2023"
                    }
                }
                ],
                "hosts": [{
                    "item": {
                        "down": "0",
                        "total": "2",
                        "up": "2"
                    }
                }
                ]
            }
            ],
            "scaninfo": [{
                "item": {
                    "numservices": "1024",
                    "protocol": "tcp",
                    "services": "1-1024",
                    "type": "syn"
                }
            }
            ],
            "verbose": [{
                "item": {
                    "level": "0"
                }
            }
            ]
        },
        "192.168.1.69": {
            "debugging": [{
                "item": {
                    "level": "0"
                }
            }
            ],
            "host": [{
                "address": [{
                    "item": {
                        "addr": "172.30.160.1",
                        "addrtype": "ipv4"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "0"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "Busy server or unknown class",
                        "values": "3B1,3C3,3D1,3DF,3ED,3FD"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938869",
                    "starttime": "1679938833"
                },
                "os": [{
                    "osmatch": [{
                        "item": {
                            "accuracy": "100",
                            "line": "69956",
                            "name": "Microsoft Windows 10 1809 - 1909"
                        },
                        "osclass": [{
                            "cpe": ["cpe:/o:microsoft:windows_10"],
                            "item": {
                                "accuracy": "100",
                                "osfamily": "Windows",
                                "osgen": "10",
                                "type": "general purpose",
                                "vendor": "Microsoft"
                            }
                        }
                        ]
                    }
                    ],
                    "portused": [{
                        "item": {
                            "portid": "21",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }, {
                        "item": {
                            "portid": "1",
                            "proto": "tcp",
                            "state": "closed"
                        }
                    }, {
                        "item": {
                            "portid": "31347",
                            "proto": "udp",
                            "state": "closed"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1016",
                                "reason": "resets"
                            }
                        }
                        ],
                        "item": {
                            "count": "1016",
                            "state": "closed"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "21",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "ftp",
                                "servicefp": "SF-Port21-TCP:V=7.91%I=7%D=3/27%Time=6421D518%P=i686-pc-windows-windows%r(NULL,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(GenericLines,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(Help,17C,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n214-The\\x20following\\x20commands\\x20are\\x20recognized\\.\\r\\n\\x20NOP\\x20\\x20USER\\x20TYPE\\x20SYST\\x20SIZE\\x20RNTO\\x20RNFR\\x20RMD\\x20\\x20REST\\x20QUIT\\r\\n\\x20HELP\\x20XMKD\\x20MLST\\x20MKD\\x20\\x20EPSV\\x20XCWD\\x20NOOP\\x20AUTH\\x20OPTS\\x20DELE\\r\\n\\x20CWD\\x20\\x20CDUP\\x20APPE\\x20STOR\\x20ALLO\\x20RETR\\x20PWD\\x20\\x20FEAT\\x20CLNT\\x20MFMT\\r\\n\\x20MODE\\x20XRMD\\x20PROT\\x20ADAT\\x20ABOR\\x20XPWD\\x20MDTM\\x20LIST\\x20MLSD\\x20PBSZ\\r\\n\\x20NLST\\x20EPRT\\x20PASS\\x20STRU\\x20PASV\\x20STAT\\x20PORT\\r\\n214\\x20Help\\x20ok\\.\\r\\n\")%r(GetRequest,76,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n501\\x20What\\x20are\\x20you\\x20trying\\x20to\\x20do\\?\\x20Go\\x20away\\.\\r\\n\")%r(HTTPOptions,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RTSPRequest,61,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n500\\x20Wrong\\x20command\\.\\r\\n\")%r(RPCCheck,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSVersionBindReqTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(DNSStatusRequestTCP,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(SSLSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TerminalServerCookie,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\")%r(TLSSessionReq,4D,\"220-FileZilla\\x20Server\\x201\\.5\\.1\\r\\n220\\x20Please\\x20visit\\x20https://filezilla-project\\.org/\\r\\n\");"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "80",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/a:microsoft:internet_information_server:10.0", "cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "http",
                                "ostype": "Windows",
                                "product": "Microsoft IIS httpd",
                                "version": "10.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "135",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "msrpc",
                                "ostype": "Windows",
                                "product": "Microsoft Windows RPC"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "137",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "netbios-ns"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "no-response",
                                "reason_ttl": "0",
                                "state": "filtered"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "139",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "netbios-ssn",
                                "ostype": "Windows",
                                "product": "Microsoft Windows netbios-ssn"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "445",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "microsoft-ds"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "903",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "tunnel": "ssl",
                                "version": "1.10"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "913",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "10",
                                "extrainfo": "Uses VNC, SOAP",
                                "method": "probed",
                                "name": "vmware-auth",
                                "product": "VMware Authentication Daemon",
                                "version": "1.0"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "localhost-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "256",
                        "values": "DE820A7C,A353FE4A,D0FBB54E,B38CF83D,8B67C730,2CE3F400"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "none returned (unsupported)"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "241",
                        "srtt": "128",
                        "to": "100000"
                    }
                }
                ]
            }, {
                "address": [{
                    "item": {
                        "addr": "192.168.1.69",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "FC:AA:14:2B:A5:31",
                        "addrtype": "mac",
                        "vendor": "Giga-byte Technology"
                    }
                }
                ],
                "distance": [{
                    "item": {
                        "value": "1"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "ipidsequence": [{
                    "item": {
                        "class": "Incremental",
                        "values": "5DE1,5DE2,5DE3,5DE4,5DE5,5DE6"
                    }
                }
                ],
                "item": {
                    "endtime": "1679938884",
                    "starttime": "1679938833"
                },
                "os": [{
                    "portused": [{
                        "item": {
                            "portid": "135",
                            "proto": "tcp",
                            "state": "open"
                        }
                    }
                    ]
                }
                ],
                "ports": [{
                    "extraports": [{
                        "extrareasons": [{
                            "item": {
                                "count": "1021",
                                "reason": "no-responses"
                            }
                        }
                        ],
                        "item": {
                            "count": "1021",
                            "state": "filtered"
                        }
                    }
                    ],
                    "port": [{
                        "item": {
                            "portid": "135",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "msrpc",
                                "ostype": "Windows",
                                "product": "Microsoft Windows RPC"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "139",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "cpe": ["cpe:/o:microsoft:windows"],
                            "item": {
                                "conf": "10",
                                "method": "probed",
                                "name": "netbios-ssn",
                                "ostype": "Windows",
                                "product": "Microsoft Windows netbios-ssn"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }, {
                        "item": {
                            "portid": "445",
                            "protocol": "tcp"
                        },
                        "service": [{
                            "item": {
                                "conf": "3",
                                "method": "table",
                                "name": "microsoft-ds"
                            }
                        }
                        ],
                        "state": [{
                            "item": {
                                "reason": "syn-ack",
                                "reason_ttl": "128",
                                "state": "open"
                            }
                        }
                        ]
                    }
                    ]
                }
                ],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ],
                "tcpsequence": [{
                    "item": {
                        "difficulty": "Good luck!",
                        "index": "259",
                        "values": "D96509E5,177DA029,F0C7BA90,AF8BD34C,32438EFA,D6B4C06F"
                    }
                }
                ],
                "tcptssequence": [{
                    "item": {
                        "class": "none returned (unsupported)"
                    }
                }
                ],
                "times": [{
                    "item": {
                        "rttvar": "819",
                        "srtt": "1560",
                        "to": "100000"
                    }
                }
                ]
            }
            ],
            "hosthint": [{
                "address": [{
                    "item": {
                        "addr": "192.168.1.69",
                        "addrtype": "ipv4"
                    }
                }, {
                    "item": {
                        "addr": "FC:AA:14:2B:A5:31",
                        "addrtype": "mac",
                        "vendor": "Giga-byte Technology"
                    }
                }
                ],
                "hostnames": ["\r\n"],
                "status": [{
                    "item": {
                        "reason": "arp-response",
                        "reason_ttl": "0",
                        "state": "up"
                    }
                }
                ]
            }
            ],
            "item": {
                "args": "nmap --host-timeout=120s -T4 -sV -O -oX - -p1-1024  192.168.1.69",
                "scanner": "nmap",
                "start": "1679938832",
                "startstr": "Mon Mar 27 10:40:32 2023",
                "version": "7.91",
                "xmloutputversion": "1.05"
            },
            "runstats": [{
                "finished": [{
                    "item": {
                        "elapsed": "52.99",
                        "exit": "success",
                        "summary": "Nmap done at Mon Mar 27 10:41:24 2023; 2 IP addresses (2 hosts up) scanned in 52.99 seconds",
                        "time": "1679938884",
                        "timestr": "Mon Mar 27 10:41:24 2023"
                    }
                }
                ],
                "hosts": [{
                    "item": {
                        "down": "0",
                        "total": "2",
                        "up": "2"
                    }
                }
                ]
            }
            ],
            "scaninfo": [{
                "item": {
                    "numservices": "1024",
                    "protocol": "tcp",
                    "services": "1-1024",
                    "type": "syn"
                }
            }
            ],
            "verbose": [{
                "item": {
                    "level": "0"
                }
            }
            ]
        }
    }


    // const nmapPromise = new Promise((resolve, reject) => {
    //     libnmapp.scan(opts, function(err: any, report: any) {
    //         if (err) throw err;
    //
    //         // for (let item in report) {
    //         //     console.log(JSON.stringify(report[item], null, 2));
    //         // }
    //
    //         const results = [];
    //
    //         console.log('RAW');
    //         console.log('Entire Report!!! ' + JSON.stringify(report));
    //
    //         console.log('LOOP');
    //         for (let item in report) {
    //             console.log(JSON.stringify(report[item], null, 2));
    //         }
    //
    //         console.log('MAIn LOOP');
    //         for (const item in report) {
    //             const host = report[item];
    //             const hostArr = host.host
    //
    //             // Do something with each item in the host array
    //             for (const hostItem of hostArr) {
    //                 const addressArr = hostItem.address;
    //                 const portsArr = hostItem.ports;
    //                 const osArr = hostItem.os;
    //
    //                 for (const addressItem of addressArr) {
    //                     const addr = addressItem.item.addr;
    //
    //                     if (mainList.includes(addr)) {
    //                         // Address matches
    //                         console.log('Found IP: ' + addr);
    //                         console.log('Ports are:')
    //                         console.log(JSON.stringify(portsArr));
    //                         console.log('OS are:')
    //                         console.log(JSON.stringify(osArr));
    //
    //                         // // Create new object of relevant information
    //                         // let hostResult = {addr: {
    //                         //     'services':
    //                         //     }}
    //                     }
    //                 }
    //             }
    //         }
    //
    //         resolve('Nice');
    //     });
    // });
        // nmapscan.on('complete', function (data: any) {
        //     console.log(JSON.stringify(data));
        //     // for (let i = 0; i < data.length; i++) {
        //     //     ipAddresses.push(data[i].ip)
        //     // }
        //     // console.log(ipAddresses);
        //
        //     resolve(JSON.stringify(data));
        // });
        //
        // nmapscan.on('error', function (error: any) {
        //     console.log('Error in the Port Scanning function: ' + error);
        //     reject(error);
        // });
    // });
    //
    // nmapscan.startScan(); // Start the nmap scan
    let nmapScanResult = await nmapPromise; // Wait for the promise to resolve
    // // console.log('Scanning Ports');
    // console.log('OS and Port scan time: ' + nmapscan.scanTime);
    // // TODO: Error handling
    return 'nice';

    // console.log('Scanning Ports');
    // console.log(devices);
    // return devices;
    // return 'Ports scanning not yet implemented';
}

export async function scanServices() {
    // TODO: Scan services and return the output
    return 'Scan services not yet implemented';
}

async function getLocalIP() {
    const interfaces = networkInterfaces();
    let discoveredIP = null;
    // console.log(interfaces);

    // Iterate through all network interfaces
    for (const name of Object.keys(interfaces)) {
        const iface = interfaces[name];

        // Check if the interface is associated with a virtual machine
        if (name.toLocaleLowerCase().startsWith('virtual') || name.toLocaleLowerCase().startsWith('vm') || name.toLocaleLowerCase().startsWith('vbox')) {
            continue;
        }

        // Iterate through list of IP addresses associated with the interface
        for (const address of iface) {
            if (address.family === 'IPv4' && !address.internal && address.mac !== '00:00:00:00:00:00' && address.netmask === '255.255.255.0') {
                discoveredIP = address.address + ":" + address.netmask;
                break;
            }
        }

        if (discoveredIP) {
            break;
        }
    }

    if (!discoveredIP) {
        // An Interface could not be found
        // TODO: Handle error
    }

    return discoveredIP;
}