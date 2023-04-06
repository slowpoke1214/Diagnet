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
    // console.log('Current IP: ' + IP);
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

    console.log('Scanning devices time: ', nmapscan.scanTime);
    // TODO: Error handling
    return nmapScanResult;
}

export async function scanPorts(event: any, devices: string) : Promise<unknown> {
    // TODO: Scan ports and return output
    let mainList: string[] = [];
    for (let i = 0; i < devices.length; i++) {
        // console.log('Currently at device: ' + devices[i]);
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
            '-sC',

        ],
        range: mainList,
        json: true
    };

    const nmapPromise = new Promise((resolve, reject) => {
        libnmapp.scan(opts, function(err: any, report: any) {
            if (err) throw err;

            // for (let item in report) {
            //     console.log(JSON.stringify(report[item]));
            // }

            // console.log('THE SINGLE IP:')
            // console.log(JSON.stringify(report));

            let results = []

// Create new object of relevant information
// let hostResult = {addr: {
//         'services': serviceResults,
//         'os': [{'OSName': []}],
//     }}


            for (const item in report) {
                const host = report[item];
                const hostArr = host.host

                // Do something with each item in the host array
                for (const hostItem of hostArr) {
                    const addressArr = hostItem.address;
                    const portsArr = hostItem.ports;
                    const osArr = hostItem.os;

                    for (const addressItem of addressArr) {
                        const addr = addressItem.item.addr;

                        if (mainList.includes(addr)) {
                            // Address matches
                            // console.log('Found IP: ' + addr);
                            // console.log('Ports are:')
                            // console.log(JSON.stringify(portsArr));
                            // console.log('OS are:')
                            // console.log(JSON.stringify(osArr));

                            let serviceResults = []

                            let osName = null

                            try {
                                for (const osArrItem of osArr) {
                                    const osMatchArr = osArrItem.osmatch;

                                    if (osMatchArr[0].item.name) {
                                        osName = osMatchArr[0].item.name;
                                    }
                                }
                            } catch (e) {
                                // Ignore any values that aren't found
                            }

                            try {
                                // Ports Iteration
                                for (const portsArrItem of portsArr) {
                                    // Port number
                                    // Service Name
                                    // CPE

                                    // Reset the service reults for this iteration
                                    serviceResults = []

                                    const mainPortsArr = portsArrItem.port;
                                    for (const mainPortsArrItem of mainPortsArr) {
                                        const serviceArr = mainPortsArrItem.service;

                                        let serviceCPE = null;
                                        let serviceVersion = null;
                                        let serviceName = null;
                                        let servicePort = null;

                                        if (mainPortsArrItem.item.portid) {
                                            servicePort = mainPortsArrItem.item.portid;
                                        }

                                        for (const serviceArrItem of serviceArr) {
                                            if (serviceArrItem.item.version) {
                                                serviceCPE = serviceArrItem.cpe[0];
                                                serviceVersion = serviceArrItem.item.version;
                                            }

                                            if (serviceArrItem.item.product) {
                                                serviceName = serviceArrItem.item.product;
                                            }
                                            serviceResults.push({[serviceName]: {'CPE': serviceCPE, 'version': serviceVersion, 'port': servicePort}})
                                        }
                                    }

                                    // results.push({[addr]: {'ports': [serviceResults], 'os': [osName]}})
                                    let nicee = JSON.stringify(results[0]);
                                    // const serviceArr = portsArrItem.service;

                                    // for (const serviceArrItem of serviceArr) {
                                    //     const serviceName = serviceArrItem.item.name;
                                    //     const serviceCPE = serviceArrItem.cpe[0];
                                    //     const serviceVersion = serviceArrItem.item.version;
                                    // }
                                }
                            } catch (e) {
                                // Ignore any values that aren't found
                            }
                            // console.log('reaches! !')
                            results.push({[addr]: {'ports': serviceResults, 'os': [osName]}})
                        }
                    }
                }
            }

            resolve(JSON.stringify(results));
        });
    });
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
    // const nmapScanResult = JSON.stringify([{"192.168.1.1":{"os":[null],"ports":[[]]}},{"192.168.1.103":{"os":[null],"ports":[[]]}},{"192.168.1.104":{"os":["OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1 or 4.4)"],"ports":[[{"Dropbear sshd":{"CPE":null,"port":"22","version":null}}]]}},{"192.168.1.11":{"os":[null],"ports":[[]]}},{"192.168.1.111":{"os":[null],"ports":[[]]}},{"192.168.1.13":{"os":["Linux 4.15 - 5.6"],"ports":[[{"OpenSSH":{"CPE":"cpe:/a:openbsd:openssh:8.2p1","port":"22","version":"8.2p1 Ubuntu 4ubuntu0.5"}},{"nginx":{"CPE":"cpe:/a:igor_sysoev:nginx:1.18.0","port":"80","version":"1.18.0"}}]]}},{"192.168.1.139":{"os":[null],"ports":[[]]}},{"192.168.1.69":{"os":[null],"ports":[[{"Microsoft Windows RPC":{"CPE":null,"port":"135","version":null}},{"Microsoft Windows netbios-ssn":{"CPE":null,"port":"139","version":null}},{"null":{"CPE":null,"version":null,"port":"445"}}]]}}]);
    // console.log('Scanning Ports');
    // console.log('OS and Port scan time: ' + nmapscan.scanTime);
    // // TODO: Error handling
    // console.log(nmapScanResult);
    return nmapScanResult;

    // console.log('Scanning Ports');
    // console.log(devices);
    // return devices;
    // return 'Ports scanning not yet implemented';
}

export async function scanCVE(event: any, CVEDeviceInfo: string) : Promise<unknown> {
    // TODO: Use NIST NVD API to check for CVE

    const NISTUrl = 'https://services.nvd.nist.gov/rest/json/cves/1.0/';
    const cpeNameParam = '?cpeName=';
    const results = [];

    const deviceInfo = JSON.parse(CVEDeviceInfo);
    // Loop over items
    console.log('ENTIRE LIST: ', JSON.stringify(deviceInfo))
    for (const data of deviceInfo) {
        // Take JSON object from the array
        for (const addr of Object.keys(data)) {
            // Iterate each JSON key/value pair

            const servicesArr = [];
            for (const service of data[addr].ports) {
                // Iterate through each service in the address

                console.log('IP ADDRESS: ', addr)
                const serviceName = Object.keys(service)[0] || null
                console.log('HERE SERVICE: ', serviceName);
                // Check if service exists
                if (serviceName) {
                    let cpeResult;
                    const cpe = service[serviceName].CPE || null;
                    // Check if the CPE is set
                    if (cpe) {
                        // CPE Exists, use API
                        const res = await fetch(`${NISTUrl}${cpeNameParam}${encodeURIComponent(cpe)}`);
                        cpeResult = await res.json();
                        console.log('\n NICE::!!!!!!!!!!!!!!!!!!11 \n \n');
                        // console.log(JSON.stringify(cpeResult));

                        // Timeout for 6 seconds due to rate limiting by NIST API
                        await new Promise(resolve => setTimeout(resolve, 6000));

                    } else {
                        // CPE has not been set
                        cpeResult = [];
                    }

                    // Add to results array
                    servicesArr.push({
                        "serviceName": serviceName,
                        "CVEData": cpeResult
                    })
                }

            }
            // End of address, add to list
            results.push({
                "address": addr,
                "data": servicesArr
            })
        }

    }
    console.log('FINAL RESULTS:: \n');
    console.log(JSON.stringify(results));

    const testResults = [{
        "address": "192.168.1.13",
        "data": [{
            "serviceName": "OpenSSH",
            "CVEData": {
                "resultsPerPage": 9,
                "startIndex": 0,
                "totalResults": 9,
                "result": {
                    "CVE_data_type": "CVE",
                    "CVE_data_format": "MITRE",
                    "CVE_data_version": "4.0",
                    "CVE_data_timestamp": "2023-04-01T03:36Z",
                    "CVE_Items": [{
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2023-28531",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "NVD-CWE-noinfo"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://www.openwall.com/lists/oss-security/2023/03/15/8",
                                    "name": "https://www.openwall.com/lists/oss-security/2023/03/15/8",
                                    "refsource": "MISC",
                                    "tags": ["Mailing List", "Release Notes"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "ssh-add in OpenSSH before 9.3 adds smartcard keys to ssh-agent without the intended per-hop destination constraints."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "9.3",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "HIGH",
                                    "availabilityImpact": "HIGH",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL"
                                },
                                "exploitabilityScore": 3.9,
                                "impactScore": 5.9
                            }
                        },
                        "publishedDate": "2023-03-17T04:15Z",
                        "lastModifiedDate": "2023-03-23T14:07Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2020-15778",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-78"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://github.com/cpandya2909/CVE-2020-15778/",
                                    "name": "https://github.com/cpandya2909/CVE-2020-15778/",
                                    "refsource": "MISC",
                                    "tags": ["Exploit", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/security.html",
                                    "name": "https://www.openssh.com/security.html",
                                    "refsource": "MISC",
                                    "tags": ["Vendor Advisory"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20200731-0007/",
                                    "name": "https://security.netapp.com/advisory/ntap-20200731-0007/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://news.ycombinator.com/item?id=25005567",
                                    "name": "https://news.ycombinator.com/item?id=25005567",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.gentoo.org/glsa/202212-06",
                                    "name": "GLSA-202212-06",
                                    "refsource": "GENTOO",
                                    "tags": ["Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "** DISPUTED ** scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of \"anomalous argument transfers\" because that could \"stand a great chance of breaking existing workflows.\""
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:8.3:p1:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:8.3:-:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "8.3",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:a700s_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:steelstore_cloud_integrated_storage:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:active_iq_unified_manager:*:*:*:*:*:vmware_vsphere:*:*",
                                    "versionStartIncluding": "9.5",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:h:netapp:hci_storage_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:h:netapp:hci_compute_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:broadcom:fabric_operating_system:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                    "attackVector": "LOCAL",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "REQUIRED",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "HIGH",
                                    "availabilityImpact": "HIGH",
                                    "baseScore": 7.8,
                                    "baseSeverity": "HIGH"
                                },
                                "exploitabilityScore": 1.8,
                                "impactScore": 5.9
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "PARTIAL",
                                    "availabilityImpact": "PARTIAL",
                                    "baseScore": 6.8
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 8.6,
                                "impactScore": 6.4,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": true
                            }
                        },
                        "publishedDate": "2020-07-24T14:15Z",
                        "lastModifiedDate": "2023-02-24T19:43Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2021-41617",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "NVD-CWE-Other"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://www.openwall.com/lists/oss-security/2021/09/26/1",
                                    "name": "https://www.openwall.com/lists/oss-security/2021/09/26/1",
                                    "refsource": "MISC",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/txt/release-8.8",
                                    "name": "https://www.openssh.com/txt/release-8.8",
                                    "refsource": "MISC",
                                    "tags": ["Release Notes", "Vendor Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/security.html",
                                    "name": "https://www.openssh.com/security.html",
                                    "refsource": "MISC",
                                    "tags": ["Vendor Advisory"]
                                }, {
                                    "url": "https://bugzilla.suse.com/show_bug.cgi?id=1190975",
                                    "name": "https://bugzilla.suse.com/show_bug.cgi?id=1190975",
                                    "refsource": "CONFIRM",
                                    "tags": ["Issue Tracking", "Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6XJIONMHMKZDTMH6BQR5TNLF2WDCGWED/",
                                    "name": "FEDORA-2021-1f7339271d",
                                    "refsource": "FEDORA",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }, {
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/W44V2PFQH5YLRN6ZJTVRKAD7CU6CYYET/",
                                    "name": "FEDORA-2021-f8df0f8563",
                                    "refsource": "FEDORA",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20211014-0004/",
                                    "name": "https://security.netapp.com/advisory/ntap-20211014-0004/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KVI7RWM2JLNMWTOFK6BDUSGNOIPZYPUT/",
                                    "name": "FEDORA-2021-fa0e94198f",
                                    "refsource": "FEDORA",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.oracle.com/security-alerts/cpuapr2022.html",
                                    "name": "https://www.oracle.com/security-alerts/cpuapr2022.html",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.oracle.com/security-alerts/cpujul2022.html",
                                    "name": "N/A",
                                    "refsource": "N/A",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://www.starwindsoftware.com/security/sw-20220805-0001/",
                                    "name": "https://www.starwindsoftware.com/security/sw-20220805-0001/",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://www.tenable.com/plugins/nessus/154174",
                                    "name": "https://www.tenable.com/plugins/nessus/154174",
                                    "refsource": "MISC",
                                    "tags": []
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used, allows privilege escalation because supplemental groups are not initialized as expected. Helper programs for AuthorizedKeysCommand and AuthorizedPrincipalsCommand may run with privileges associated with group memberships of the sshd process, if the configuration specifies running the command as a different user."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "6.2",
                                    "versionEndExcluding": "8.8",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:fedoraproject:fedora:33:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:ontap_select_deploy_administration_utility:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:clustered_data_ontap:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:aff_a250_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:aff_a250:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:aff_500f_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:aff_500f:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:oracle:http_server:12.2.1.2.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:oracle:http_server:12.2.1.3.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:oracle:http_server:12.2.1.4.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:oracle:zfs_storage_appliance_kit:8.8:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:starwindsoftware:starwind_virtual_san:v8r13:14398:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                    "attackVector": "LOCAL",
                                    "attackComplexity": "HIGH",
                                    "privilegesRequired": "LOW",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "HIGH",
                                    "availabilityImpact": "HIGH",
                                    "baseScore": 7,
                                    "baseSeverity": "HIGH"
                                },
                                "exploitabilityScore": 1,
                                "impactScore": 5.9
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:L/AC:M/Au:N/C:P/I:P/A:P",
                                    "accessVector": "LOCAL",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "PARTIAL",
                                    "availabilityImpact": "PARTIAL",
                                    "baseScore": 4.4
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 3.4,
                                "impactScore": 6.4,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": false
                            }
                        },
                        "publishedDate": "2021-09-26T19:15Z",
                        "lastModifiedDate": "2023-02-14T14:15Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2021-36368",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-287"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://github.com/openssh/openssh-portable/pull/258",
                                    "name": "https://github.com/openssh/openssh-portable/pull/258",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://docs.ssh-mitm.at/trivialauth.html",
                                    "name": "https://docs.ssh-mitm.at/trivialauth.html",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://bugzilla.mindrot.org/show_bug.cgi?id=3316",
                                    "name": "https://bugzilla.mindrot.org/show_bug.cgi?id=3316",
                                    "refsource": "CONFIRM",
                                    "tags": ["Issue Tracking", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/security.html",
                                    "name": "https://www.openssh.com/security.html",
                                    "refsource": "MISC",
                                    "tags": ["Vendor Advisory"]
                                }, {
                                    "url": "https://security-tracker.debian.org/tracker/CVE-2021-36368",
                                    "name": "https://security-tracker.debian.org/tracker/CVE-2021-36368",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "** DISPUTED ** An issue was discovered in OpenSSH before 8.9. If a client is using public-key authentication with agent forwarding but without -oLogLevel=verbose, and an attacker has silently modified the server to support the None authentication option, then the user cannot determine whether FIDO authentication is going to confirm that the user wishes to connect to that server, or that the user wishes to allow that server to connect to a different server on the user's behalf. NOTE: the vendor's position is \"this is not an authentication bypass, since nothing is being bypassed.\""
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "8.9",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "HIGH",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "LOW",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 3.7,
                                    "baseSeverity": "LOW"
                                },
                                "exploitabilityScore": 2.2,
                                "impactScore": 1.4
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:H/Au:N/C:P/I:N/A:N",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "HIGH",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 2.6
                                },
                                "severity": "LOW",
                                "exploitabilityScore": 4.9,
                                "impactScore": 2.9,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": false
                            }
                        },
                        "publishedDate": "2022-03-13T00:15Z",
                        "lastModifiedDate": "2022-07-01T17:21Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2021-28041",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-415"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://github.com/openssh/openssh-portable/commit/e04fd6dde16de1cdc5a4d9946397ff60d96568db",
                                    "name": "https://github.com/openssh/openssh-portable/commit/e04fd6dde16de1cdc5a4d9946397ff60d96568db",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/txt/release-8.5",
                                    "name": "https://www.openssh.com/txt/release-8.5",
                                    "refsource": "MISC",
                                    "tags": ["Release Notes", "Vendor Advisory"]
                                }, {
                                    "url": "https://www.openwall.com/lists/oss-security/2021/03/03/1",
                                    "name": "https://www.openwall.com/lists/oss-security/2021/03/03/1",
                                    "refsource": "MISC",
                                    "tags": ["Mailing List", "Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/security.html",
                                    "name": "https://www.openssh.com/security.html",
                                    "refsource": "MISC",
                                    "tags": ["Not Applicable", "Vendor Advisory"]
                                }, {
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TXST2CML2MWY3PNVUXX7FFJE3ATJMNVZ/",
                                    "name": "FEDORA-2021-f68a5a75ba",
                                    "refsource": "FEDORA",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20210416-0002/",
                                    "name": "https://security.netapp.com/advisory/ntap-20210416-0002/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.gentoo.org/glsa/202105-35",
                                    "name": "GLSA-202105-35",
                                    "refsource": "GENTOO",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KQWGII3LQR4AOTPPFXGMTYE7UDEWIUKI/",
                                    "name": "FEDORA-2021-1d3698089d",
                                    "refsource": "FEDORA",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.oracle.com//security-alerts/cpujul2021.html",
                                    "name": "N/A",
                                    "refsource": "N/A",
                                    "tags": ["Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "ssh-agent in OpenSSH before 8.5 has a double free that may be relevant in a few less-common scenarios, such as unconstrained agent-socket access on a legacy operating system, or the forwarding of an agent to an attacker-controlled host."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "8.2",
                                    "versionEndExcluding": "8.5",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:fedoraproject:fedora:33:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:cloud_backup:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:hci_compute_node_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:hci_compute_node:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:hci_storage_node_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:hci_storage_node:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:oracle:zfs_storage_appliance:8.8:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:oracle:communications_offline_mediation_controller:12.0.0.3.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "HIGH",
                                    "privilegesRequired": "LOW",
                                    "userInteraction": "REQUIRED",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "HIGH",
                                    "availabilityImpact": "HIGH",
                                    "baseScore": 7.1,
                                    "baseSeverity": "HIGH"
                                },
                                "exploitabilityScore": 1.2,
                                "impactScore": 5.9
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:H/Au:S/C:P/I:P/A:P",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "HIGH",
                                    "authentication": "SINGLE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "PARTIAL",
                                    "availabilityImpact": "PARTIAL",
                                    "baseScore": 4.6
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 3.9,
                                "impactScore": 6.4,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": true
                            }
                        },
                        "publishedDate": "2021-03-05T21:15Z",
                        "lastModifiedDate": "2022-05-20T20:47Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2020-14145",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-203"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://github.com/openssh/openssh-portable/compare/V_8_3_P1...V_8_4_P1",
                                    "name": "https://github.com/openssh/openssh-portable/compare/V_8_3_P1...V_8_4_P1",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.fzi.de/en/news/news/detail-en/artikel/fsa-2020-2-ausnutzung-eines-informationslecks-fuer-gezielte-mitm-angriffe-auf-ssh-clients/",
                                    "name": "https://www.fzi.de/en/news/news/detail-en/artikel/fsa-2020-2-ausnutzung-eines-informationslecks-fuer-gezielte-mitm-angriffe-auf-ssh-clients/",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20200709-0004/",
                                    "name": "https://security.netapp.com/advisory/ntap-20200709-0004/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "http://www.openwall.com/lists/oss-security/2020/12/02/1",
                                    "name": "[oss-security] 20201202 Some mitigation for openssh CVE-2020-14145",
                                    "refsource": "MLIST",
                                    "tags": ["Mailing List", "Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://anongit.mindrot.org/openssh.git/commit/?id=b3855ff053f5078ec3d3c653cdaedefaa5fc362d",
                                    "name": "https://anongit.mindrot.org/openssh.git/commit/?id=b3855ff053f5078ec3d3c653cdaedefaa5fc362d",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://github.com/ssh-mitm/ssh-mitm/blob/master/ssh_proxy_server/plugins/session/cve202014145.py",
                                    "name": "https://github.com/ssh-mitm/ssh-mitm/blob/master/ssh_proxy_server/plugins/session/cve202014145.py",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://docs.ssh-mitm.at/CVE-2020-14145.html",
                                    "name": "https://docs.ssh-mitm.at/CVE-2020-14145.html",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.gentoo.org/glsa/202105-35",
                                    "name": "GLSA-202105-35",
                                    "refsource": "GENTOO",
                                    "tags": ["Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "The client side in OpenSSH 5.7 through 8.4 has an Observable Discrepancy leading to an information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target initial connection attempts (where no host key for the server has been cached by the client). NOTE: some reports state that 8.5 and 8.6 are also affected."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:8.4:-:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "5.7",
                                    "versionEndExcluding": "8.4",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:8.5:-:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:8.6:-:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:aff_a700s_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:aff_a700s:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:steelstore_cloud_integrated_storage:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:ontap_select_deploy_administration_utility:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:active_iq_unified_manager:*:*:*:*:*:vmware_vsphere:*:*",
                                    "versionStartIncluding": "9.5",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:h:netapp:hci_storage_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:h:netapp:hci_compute_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "HIGH",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 5.9,
                                    "baseSeverity": "MEDIUM"
                                },
                                "exploitabilityScore": 2.2,
                                "impactScore": 3.6
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 4.3
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 8.6,
                                "impactScore": 2.9,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": false
                            }
                        },
                        "publishedDate": "2020-06-29T18:15Z",
                        "lastModifiedDate": "2022-04-28T19:34Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2016-20012",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "NVD-CWE-Other"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://github.com/openssh/openssh-portable/blob/d0fffc88c8fe90c1815c6f4097bc8cbcabc0f3dd/auth2-pubkey.c#L261-L265",
                                    "name": "https://github.com/openssh/openssh-portable/blob/d0fffc88c8fe90c1815c6f4097bc8cbcabc0f3dd/auth2-pubkey.c#L261-L265",
                                    "refsource": "MISC",
                                    "tags": ["Exploit", "Third Party Advisory"]
                                }, {
                                    "url": "https://github.com/openssh/openssh-portable/pull/270",
                                    "name": "https://github.com/openssh/openssh-portable/pull/270",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://rushter.com/blog/public-ssh-keys/",
                                    "name": "https://rushter.com/blog/public-ssh-keys/",
                                    "refsource": "MISC",
                                    "tags": ["Exploit", "Third Party Advisory"]
                                }, {
                                    "url": "https://utcc.utoronto.ca/~cks/space/blog/tech/SSHKeysAreInfoLeak",
                                    "name": "https://utcc.utoronto.ca/~cks/space/blog/tech/SSHKeysAreInfoLeak",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20211014-0005/",
                                    "name": "https://security.netapp.com/advisory/ntap-20211014-0005/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://github.com/openssh/openssh-portable/pull/270#issuecomment-943909185",
                                    "name": "https://github.com/openssh/openssh-portable/pull/270#issuecomment-943909185",
                                    "refsource": "MISC",
                                    "tags": ["Issue Tracking", "Third Party Advisory"]
                                }, {
                                    "url": "https://github.com/openssh/openssh-portable/pull/270#issuecomment-920577097",
                                    "name": "https://github.com/openssh/openssh-portable/pull/270#issuecomment-920577097",
                                    "refsource": "MISC",
                                    "tags": ["Issue Tracking", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openwall.com/lists/oss-security/2018/08/24/1",
                                    "name": "https://www.openwall.com/lists/oss-security/2018/08/24/1",
                                    "refsource": "MISC",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "** DISPUTED ** OpenSSH through 8.7 allows remote attackers, who have a suspicion that a certain combination of username and public key is known to an SSH server, to test whether this suspicion is correct. This occurs because a challenge is sent only when that combination could be valid for a login session. NOTE: the vendor does not recognize user enumeration as a vulnerability for this product."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionEndIncluding": "8.7",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:ontap_select_deploy_administration_utility:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:clustered_data_ontap:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "LOW",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 5.3,
                                    "baseSeverity": "MEDIUM"
                                },
                                "exploitabilityScore": 3.9,
                                "impactScore": 1.4
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 4.3
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 8.6,
                                "impactScore": 2.9,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": false
                            }
                        },
                        "publishedDate": "2021-09-15T20:15Z",
                        "lastModifiedDate": "2022-04-18T18:06Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2007-2768",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-200"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "http://archives.neohapsis.com/archives/fulldisclosure/2007-04/0635.html",
                                    "name": "20070424 Re: OpenSSH - System Account Enumeration if S/Key is used",
                                    "refsource": "FULLDISC",
                                    "tags": ["Broken Link"]
                                }, {
                                    "url": "http://www.osvdb.org/34601",
                                    "name": "34601",
                                    "refsource": "OSVDB",
                                    "tags": ["Broken Link"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20191107-0002/",
                                    "name": "https://security.netapp.com/advisory/ntap-20191107-0002/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "OpenSSH, when using OPIE (One-Time Passwords in Everything) for PAM, allows remote attackers to determine the existence of certain user accounts, which displays a different response if the user account exists and is configured to use one-time passwords (OTP), a similar issue to CVE-2007-2243."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:steelstore_cloud_integrated_storage:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:h:netapp:hci_storage_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 4.3
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 8.6,
                                "impactScore": 2.9,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": false
                            }
                        },
                        "publishedDate": "2007-05-21T20:30Z",
                        "lastModifiedDate": "2021-04-01T15:32Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2008-3844",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-20"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "http://www.redhat.com/security/data/openssh-blacklist.html",
                                    "name": "http://www.redhat.com/security/data/openssh-blacklist.html",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "http://www.redhat.com/support/errata/RHSA-2008-0855.html",
                                    "name": "RHSA-2008:0855",
                                    "refsource": "REDHAT",
                                    "tags": ["Not Applicable"]
                                }, {
                                    "url": "http://www.securityfocus.com/bid/30794",
                                    "name": "30794",
                                    "refsource": "BID",
                                    "tags": ["Third Party Advisory", "VDB Entry"]
                                }, {
                                    "url": "http://securitytracker.com/id?1020730",
                                    "name": "1020730",
                                    "refsource": "SECTRACK",
                                    "tags": ["Third Party Advisory", "VDB Entry"]
                                }, {
                                    "url": "http://secunia.com/advisories/31575",
                                    "name": "31575",
                                    "refsource": "SECUNIA",
                                    "tags": ["Permissions Required", "Third Party Advisory"]
                                }, {
                                    "url": "http://secunia.com/advisories/32241",
                                    "name": "32241",
                                    "refsource": "SECUNIA",
                                    "tags": ["Permissions Required", "Third Party Advisory"]
                                }, {
                                    "url": "http://support.avaya.com/elmodocs2/security/ASA-2008-399.htm",
                                    "name": "http://support.avaya.com/elmodocs2/security/ASA-2008-399.htm",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "http://www.vupen.com/english/advisories/2008/2821",
                                    "name": "ADV-2008-2821",
                                    "refsource": "VUPEN",
                                    "tags": ["Broken Link"]
                                }, {
                                    "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/44747",
                                    "name": "openssh-rhel-backdoor(44747)",
                                    "refsource": "XF",
                                    "tags": []
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "Certain Red Hat Enterprise Linux (RHEL) 4 and 5 packages for OpenSSH, as signed in August 2008 using a legitimate Red Hat GPG key, contain an externally introduced modification (Trojan Horse) that allows the package authors to have an unknown impact.  NOTE: since the malicious packages were not distributed from any official Red Hat sources, the scope of this issue is restricted to users who may have obtained these packages through unofficial distribution points.  As of 20080827, no unofficial distributions of this software are known."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:o:redhat:enterprise_linux:4.5.z:*:as:*:*:*:*:*",
                                        "cpe_name": []
                                    }, {
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:o:redhat:enterprise_linux:4.5.z:*:es:*:*:*:*:*",
                                        "cpe_name": []
                                    }, {
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:o:redhat:enterprise_linux:5.0:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }, {
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:o:redhat:enterprise_linux_desktop:4:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }, {
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:o:redhat:enterprise_linux_desktop:5:*:client:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "COMPLETE",
                                    "integrityImpact": "COMPLETE",
                                    "availabilityImpact": "COMPLETE",
                                    "baseScore": 9.3
                                },
                                "severity": "HIGH",
                                "exploitabilityScore": 8.6,
                                "impactScore": 10,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": true
                            }
                        },
                        "publishedDate": "2008-08-27T20:41Z",
                        "lastModifiedDate": "2017-08-08T01:32Z"
                    }
                    ]
                }
            }
        }, {
            "serviceName": "nginx",
            "CVEData": {
                "resultsPerPage": 0,
                "startIndex": 0,
                "totalResults": 0,
                "result": {
                    "CVE_data_type": "CVE",
                    "CVE_data_format": "MITRE",
                    "CVE_data_version": "4.0",
                    "CVE_data_timestamp": "2023-04-01T03:36Z",
                    "CVE_Items": []
                }
            }
        }
        ]
    }, {
        "address": "192.168.1.69",
        "data": [{
            "serviceName": "OpenSSH",
            "CVEData": {
                "resultsPerPage": 9,
                "startIndex": 0,
                "totalResults": 9,
                "result": {
                    "CVE_data_type": "CVE",
                    "CVE_data_format": "MITRE",
                    "CVE_data_version": "4.0",
                    "CVE_data_timestamp": "2023-04-01T03:36Z",
                    "CVE_Items": [{
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2023-28531",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "NVD-CWE-noinfo"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://www.openwall.com/lists/oss-security/2023/03/15/8",
                                    "name": "https://www.openwall.com/lists/oss-security/2023/03/15/8",
                                    "refsource": "MISC",
                                    "tags": ["Mailing List", "Release Notes"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "ssh-add in OpenSSH before 9.3 adds smartcard keys to ssh-agent without the intended per-hop destination constraints."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "9.3",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "HIGH",
                                    "availabilityImpact": "HIGH",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL"
                                },
                                "exploitabilityScore": 3.9,
                                "impactScore": 5.9
                            }
                        },
                        "publishedDate": "2023-03-17T04:15Z",
                        "lastModifiedDate": "2023-03-23T14:07Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2020-15778",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-78"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://github.com/cpandya2909/CVE-2020-15778/",
                                    "name": "https://github.com/cpandya2909/CVE-2020-15778/",
                                    "refsource": "MISC",
                                    "tags": ["Exploit", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/security.html",
                                    "name": "https://www.openssh.com/security.html",
                                    "refsource": "MISC",
                                    "tags": ["Vendor Advisory"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20200731-0007/",
                                    "name": "https://security.netapp.com/advisory/ntap-20200731-0007/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://news.ycombinator.com/item?id=25005567",
                                    "name": "https://news.ycombinator.com/item?id=25005567",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.gentoo.org/glsa/202212-06",
                                    "name": "GLSA-202212-06",
                                    "refsource": "GENTOO",
                                    "tags": ["Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "** DISPUTED ** scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of \"anomalous argument transfers\" because that could \"stand a great chance of breaking existing workflows.\""
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:8.3:p1:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:8.3:-:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "8.3",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:a700s_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:steelstore_cloud_integrated_storage:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:active_iq_unified_manager:*:*:*:*:*:vmware_vsphere:*:*",
                                    "versionStartIncluding": "9.5",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:h:netapp:hci_storage_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:h:netapp:hci_compute_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:broadcom:fabric_operating_system:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                    "attackVector": "LOCAL",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "REQUIRED",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "HIGH",
                                    "availabilityImpact": "HIGH",
                                    "baseScore": 7.8,
                                    "baseSeverity": "HIGH"
                                },
                                "exploitabilityScore": 1.8,
                                "impactScore": 5.9
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "PARTIAL",
                                    "availabilityImpact": "PARTIAL",
                                    "baseScore": 6.8
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 8.6,
                                "impactScore": 6.4,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": true
                            }
                        },
                        "publishedDate": "2020-07-24T14:15Z",
                        "lastModifiedDate": "2023-02-24T19:43Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2021-41617",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "NVD-CWE-Other"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://www.openwall.com/lists/oss-security/2021/09/26/1",
                                    "name": "https://www.openwall.com/lists/oss-security/2021/09/26/1",
                                    "refsource": "MISC",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/txt/release-8.8",
                                    "name": "https://www.openssh.com/txt/release-8.8",
                                    "refsource": "MISC",
                                    "tags": ["Release Notes", "Vendor Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/security.html",
                                    "name": "https://www.openssh.com/security.html",
                                    "refsource": "MISC",
                                    "tags": ["Vendor Advisory"]
                                }, {
                                    "url": "https://bugzilla.suse.com/show_bug.cgi?id=1190975",
                                    "name": "https://bugzilla.suse.com/show_bug.cgi?id=1190975",
                                    "refsource": "CONFIRM",
                                    "tags": ["Issue Tracking", "Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6XJIONMHMKZDTMH6BQR5TNLF2WDCGWED/",
                                    "name": "FEDORA-2021-1f7339271d",
                                    "refsource": "FEDORA",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }, {
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/W44V2PFQH5YLRN6ZJTVRKAD7CU6CYYET/",
                                    "name": "FEDORA-2021-f8df0f8563",
                                    "refsource": "FEDORA",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20211014-0004/",
                                    "name": "https://security.netapp.com/advisory/ntap-20211014-0004/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KVI7RWM2JLNMWTOFK6BDUSGNOIPZYPUT/",
                                    "name": "FEDORA-2021-fa0e94198f",
                                    "refsource": "FEDORA",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.oracle.com/security-alerts/cpuapr2022.html",
                                    "name": "https://www.oracle.com/security-alerts/cpuapr2022.html",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.oracle.com/security-alerts/cpujul2022.html",
                                    "name": "N/A",
                                    "refsource": "N/A",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://www.starwindsoftware.com/security/sw-20220805-0001/",
                                    "name": "https://www.starwindsoftware.com/security/sw-20220805-0001/",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://www.tenable.com/plugins/nessus/154174",
                                    "name": "https://www.tenable.com/plugins/nessus/154174",
                                    "refsource": "MISC",
                                    "tags": []
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used, allows privilege escalation because supplemental groups are not initialized as expected. Helper programs for AuthorizedKeysCommand and AuthorizedPrincipalsCommand may run with privileges associated with group memberships of the sshd process, if the configuration specifies running the command as a different user."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "6.2",
                                    "versionEndExcluding": "8.8",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:fedoraproject:fedora:33:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:ontap_select_deploy_administration_utility:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:clustered_data_ontap:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:aff_a250_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:aff_a250:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:aff_500f_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:aff_500f:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:oracle:http_server:12.2.1.2.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:oracle:http_server:12.2.1.3.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:oracle:http_server:12.2.1.4.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:oracle:zfs_storage_appliance_kit:8.8:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:starwindsoftware:starwind_virtual_san:v8r13:14398:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                    "attackVector": "LOCAL",
                                    "attackComplexity": "HIGH",
                                    "privilegesRequired": "LOW",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "HIGH",
                                    "availabilityImpact": "HIGH",
                                    "baseScore": 7,
                                    "baseSeverity": "HIGH"
                                },
                                "exploitabilityScore": 1,
                                "impactScore": 5.9
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:L/AC:M/Au:N/C:P/I:P/A:P",
                                    "accessVector": "LOCAL",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "PARTIAL",
                                    "availabilityImpact": "PARTIAL",
                                    "baseScore": 4.4
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 3.4,
                                "impactScore": 6.4,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": false
                            }
                        },
                        "publishedDate": "2021-09-26T19:15Z",
                        "lastModifiedDate": "2023-02-14T14:15Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2021-36368",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-287"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://github.com/openssh/openssh-portable/pull/258",
                                    "name": "https://github.com/openssh/openssh-portable/pull/258",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://docs.ssh-mitm.at/trivialauth.html",
                                    "name": "https://docs.ssh-mitm.at/trivialauth.html",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://bugzilla.mindrot.org/show_bug.cgi?id=3316",
                                    "name": "https://bugzilla.mindrot.org/show_bug.cgi?id=3316",
                                    "refsource": "CONFIRM",
                                    "tags": ["Issue Tracking", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/security.html",
                                    "name": "https://www.openssh.com/security.html",
                                    "refsource": "MISC",
                                    "tags": ["Vendor Advisory"]
                                }, {
                                    "url": "https://security-tracker.debian.org/tracker/CVE-2021-36368",
                                    "name": "https://security-tracker.debian.org/tracker/CVE-2021-36368",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "** DISPUTED ** An issue was discovered in OpenSSH before 8.9. If a client is using public-key authentication with agent forwarding but without -oLogLevel=verbose, and an attacker has silently modified the server to support the None authentication option, then the user cannot determine whether FIDO authentication is going to confirm that the user wishes to connect to that server, or that the user wishes to allow that server to connect to a different server on the user's behalf. NOTE: the vendor's position is \"this is not an authentication bypass, since nothing is being bypassed.\""
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "8.9",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "HIGH",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "LOW",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 3.7,
                                    "baseSeverity": "LOW"
                                },
                                "exploitabilityScore": 2.2,
                                "impactScore": 1.4
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:H/Au:N/C:P/I:N/A:N",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "HIGH",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 2.6
                                },
                                "severity": "LOW",
                                "exploitabilityScore": 4.9,
                                "impactScore": 2.9,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": false
                            }
                        },
                        "publishedDate": "2022-03-13T00:15Z",
                        "lastModifiedDate": "2022-07-01T17:21Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2021-28041",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-415"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://github.com/openssh/openssh-portable/commit/e04fd6dde16de1cdc5a4d9946397ff60d96568db",
                                    "name": "https://github.com/openssh/openssh-portable/commit/e04fd6dde16de1cdc5a4d9946397ff60d96568db",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/txt/release-8.5",
                                    "name": "https://www.openssh.com/txt/release-8.5",
                                    "refsource": "MISC",
                                    "tags": ["Release Notes", "Vendor Advisory"]
                                }, {
                                    "url": "https://www.openwall.com/lists/oss-security/2021/03/03/1",
                                    "name": "https://www.openwall.com/lists/oss-security/2021/03/03/1",
                                    "refsource": "MISC",
                                    "tags": ["Mailing List", "Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openssh.com/security.html",
                                    "name": "https://www.openssh.com/security.html",
                                    "refsource": "MISC",
                                    "tags": ["Not Applicable", "Vendor Advisory"]
                                }, {
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TXST2CML2MWY3PNVUXX7FFJE3ATJMNVZ/",
                                    "name": "FEDORA-2021-f68a5a75ba",
                                    "refsource": "FEDORA",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20210416-0002/",
                                    "name": "https://security.netapp.com/advisory/ntap-20210416-0002/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.gentoo.org/glsa/202105-35",
                                    "name": "GLSA-202105-35",
                                    "refsource": "GENTOO",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KQWGII3LQR4AOTPPFXGMTYE7UDEWIUKI/",
                                    "name": "FEDORA-2021-1d3698089d",
                                    "refsource": "FEDORA",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.oracle.com//security-alerts/cpujul2021.html",
                                    "name": "N/A",
                                    "refsource": "N/A",
                                    "tags": ["Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "ssh-agent in OpenSSH before 8.5 has a double free that may be relevant in a few less-common scenarios, such as unconstrained agent-socket access on a legacy operating system, or the forwarding of an agent to an attacker-controlled host."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "8.2",
                                    "versionEndExcluding": "8.5",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:fedoraproject:fedora:33:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:cloud_backup:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:hci_compute_node_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:hci_compute_node:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:hci_storage_node_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:hci_storage_node:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:oracle:zfs_storage_appliance:8.8:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:oracle:communications_offline_mediation_controller:12.0.0.3.0:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "HIGH",
                                    "privilegesRequired": "LOW",
                                    "userInteraction": "REQUIRED",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "HIGH",
                                    "availabilityImpact": "HIGH",
                                    "baseScore": 7.1,
                                    "baseSeverity": "HIGH"
                                },
                                "exploitabilityScore": 1.2,
                                "impactScore": 5.9
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:H/Au:S/C:P/I:P/A:P",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "HIGH",
                                    "authentication": "SINGLE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "PARTIAL",
                                    "availabilityImpact": "PARTIAL",
                                    "baseScore": 4.6
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 3.9,
                                "impactScore": 6.4,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": true
                            }
                        },
                        "publishedDate": "2021-03-05T21:15Z",
                        "lastModifiedDate": "2022-05-20T20:47Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2020-14145",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-203"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://github.com/openssh/openssh-portable/compare/V_8_3_P1...V_8_4_P1",
                                    "name": "https://github.com/openssh/openssh-portable/compare/V_8_3_P1...V_8_4_P1",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.fzi.de/en/news/news/detail-en/artikel/fsa-2020-2-ausnutzung-eines-informationslecks-fuer-gezielte-mitm-angriffe-auf-ssh-clients/",
                                    "name": "https://www.fzi.de/en/news/news/detail-en/artikel/fsa-2020-2-ausnutzung-eines-informationslecks-fuer-gezielte-mitm-angriffe-auf-ssh-clients/",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20200709-0004/",
                                    "name": "https://security.netapp.com/advisory/ntap-20200709-0004/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "http://www.openwall.com/lists/oss-security/2020/12/02/1",
                                    "name": "[oss-security] 20201202 Some mitigation for openssh CVE-2020-14145",
                                    "refsource": "MLIST",
                                    "tags": ["Mailing List", "Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://anongit.mindrot.org/openssh.git/commit/?id=b3855ff053f5078ec3d3c653cdaedefaa5fc362d",
                                    "name": "https://anongit.mindrot.org/openssh.git/commit/?id=b3855ff053f5078ec3d3c653cdaedefaa5fc362d",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://github.com/ssh-mitm/ssh-mitm/blob/master/ssh_proxy_server/plugins/session/cve202014145.py",
                                    "name": "https://github.com/ssh-mitm/ssh-mitm/blob/master/ssh_proxy_server/plugins/session/cve202014145.py",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://docs.ssh-mitm.at/CVE-2020-14145.html",
                                    "name": "https://docs.ssh-mitm.at/CVE-2020-14145.html",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.gentoo.org/glsa/202105-35",
                                    "name": "GLSA-202105-35",
                                    "refsource": "GENTOO",
                                    "tags": ["Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "The client side in OpenSSH 5.7 through 8.4 has an Observable Discrepancy leading to an information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target initial connection attempts (where no host key for the server has been cached by the client). NOTE: some reports state that 8.5 and 8.6 are also affected."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:8.4:-:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "5.7",
                                    "versionEndExcluding": "8.4",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:8.5:-:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:8.6:-:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:o:netapp:aff_a700s_firmware:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:h:netapp:aff_a700s:-:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:steelstore_cloud_integrated_storage:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:ontap_select_deploy_administration_utility:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:active_iq_unified_manager:*:*:*:*:*:vmware_vsphere:*:*",
                                    "versionStartIncluding": "9.5",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:h:netapp:hci_storage_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:h:netapp:hci_compute_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "HIGH",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 5.9,
                                    "baseSeverity": "MEDIUM"
                                },
                                "exploitabilityScore": 2.2,
                                "impactScore": 3.6
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 4.3
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 8.6,
                                "impactScore": 2.9,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": false
                            }
                        },
                        "publishedDate": "2020-06-29T18:15Z",
                        "lastModifiedDate": "2022-04-28T19:34Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2016-20012",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "NVD-CWE-Other"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "https://github.com/openssh/openssh-portable/blob/d0fffc88c8fe90c1815c6f4097bc8cbcabc0f3dd/auth2-pubkey.c#L261-L265",
                                    "name": "https://github.com/openssh/openssh-portable/blob/d0fffc88c8fe90c1815c6f4097bc8cbcabc0f3dd/auth2-pubkey.c#L261-L265",
                                    "refsource": "MISC",
                                    "tags": ["Exploit", "Third Party Advisory"]
                                }, {
                                    "url": "https://github.com/openssh/openssh-portable/pull/270",
                                    "name": "https://github.com/openssh/openssh-portable/pull/270",
                                    "refsource": "MISC",
                                    "tags": ["Patch", "Third Party Advisory"]
                                }, {
                                    "url": "https://rushter.com/blog/public-ssh-keys/",
                                    "name": "https://rushter.com/blog/public-ssh-keys/",
                                    "refsource": "MISC",
                                    "tags": ["Exploit", "Third Party Advisory"]
                                }, {
                                    "url": "https://utcc.utoronto.ca/~cks/space/blog/tech/SSHKeysAreInfoLeak",
                                    "name": "https://utcc.utoronto.ca/~cks/space/blog/tech/SSHKeysAreInfoLeak",
                                    "refsource": "MISC",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20211014-0005/",
                                    "name": "https://security.netapp.com/advisory/ntap-20211014-0005/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "https://github.com/openssh/openssh-portable/pull/270#issuecomment-943909185",
                                    "name": "https://github.com/openssh/openssh-portable/pull/270#issuecomment-943909185",
                                    "refsource": "MISC",
                                    "tags": ["Issue Tracking", "Third Party Advisory"]
                                }, {
                                    "url": "https://github.com/openssh/openssh-portable/pull/270#issuecomment-920577097",
                                    "name": "https://github.com/openssh/openssh-portable/pull/270#issuecomment-920577097",
                                    "refsource": "MISC",
                                    "tags": ["Issue Tracking", "Third Party Advisory"]
                                }, {
                                    "url": "https://www.openwall.com/lists/oss-security/2018/08/24/1",
                                    "name": "https://www.openwall.com/lists/oss-security/2018/08/24/1",
                                    "refsource": "MISC",
                                    "tags": ["Mailing List", "Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "** DISPUTED ** OpenSSH through 8.7 allows remote attackers, who have a suspicion that a certain combination of username and public key is known to an SSH server, to test whether this suspicion is correct. This occurs because a challenge is sent only when that combination could be valid for a login session. NOTE: the vendor does not recognize user enumeration as a vulnerability for this product."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "versionEndIncluding": "8.7",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:ontap_select_deploy_administration_utility:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:clustered_data_ontap:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "LOW",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 5.3,
                                    "baseSeverity": "MEDIUM"
                                },
                                "exploitabilityScore": 3.9,
                                "impactScore": 1.4
                            },
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 4.3
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 8.6,
                                "impactScore": 2.9,
                                "acInsufInfo": false,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": false
                            }
                        },
                        "publishedDate": "2021-09-15T20:15Z",
                        "lastModifiedDate": "2022-04-18T18:06Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2007-2768",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-200"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "http://archives.neohapsis.com/archives/fulldisclosure/2007-04/0635.html",
                                    "name": "20070424 Re: OpenSSH - System Account Enumeration if S/Key is used",
                                    "refsource": "FULLDISC",
                                    "tags": ["Broken Link"]
                                }, {
                                    "url": "http://www.osvdb.org/34601",
                                    "name": "34601",
                                    "refsource": "OSVDB",
                                    "tags": ["Broken Link"]
                                }, {
                                    "url": "https://security.netapp.com/advisory/ntap-20191107-0002/",
                                    "name": "https://security.netapp.com/advisory/ntap-20191107-0002/",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "OpenSSH, when using OPIE (One-Time Passwords in Everything) for PAM, allows remote attackers to determine the existence of certain user accounts, which displays a different response if the user account exists and is configured to use one-time passwords (OTP), a similar issue to CVE-2007-2243."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }, {
                                "operator": "OR",
                                "children": [],
                                "cpe_match": [{
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:steelstore_cloud_integrated_storage:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }, {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:h:netapp:hci_storage_node:-:*:*:*:*:*:*:*",
                                    "cpe_name": []
                                }
                                ]
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                    "baseScore": 4.3
                                },
                                "severity": "MEDIUM",
                                "exploitabilityScore": 8.6,
                                "impactScore": 2.9,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": false
                            }
                        },
                        "publishedDate": "2007-05-21T20:30Z",
                        "lastModifiedDate": "2021-04-01T15:32Z"
                    }, {
                        "cve": {
                            "data_type": "CVE",
                            "data_format": "MITRE",
                            "data_version": "4.0",
                            "CVE_data_meta": {
                                "ID": "CVE-2008-3844",
                                "ASSIGNER": "cve@mitre.org"
                            },
                            "problemtype": {
                                "problemtype_data": [{
                                    "description": [{
                                        "lang": "en",
                                        "value": "CWE-20"
                                    }
                                    ]
                                }
                                ]
                            },
                            "references": {
                                "reference_data": [{
                                    "url": "http://www.redhat.com/security/data/openssh-blacklist.html",
                                    "name": "http://www.redhat.com/security/data/openssh-blacklist.html",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "http://www.redhat.com/support/errata/RHSA-2008-0855.html",
                                    "name": "RHSA-2008:0855",
                                    "refsource": "REDHAT",
                                    "tags": ["Not Applicable"]
                                }, {
                                    "url": "http://www.securityfocus.com/bid/30794",
                                    "name": "30794",
                                    "refsource": "BID",
                                    "tags": ["Third Party Advisory", "VDB Entry"]
                                }, {
                                    "url": "http://securitytracker.com/id?1020730",
                                    "name": "1020730",
                                    "refsource": "SECTRACK",
                                    "tags": ["Third Party Advisory", "VDB Entry"]
                                }, {
                                    "url": "http://secunia.com/advisories/31575",
                                    "name": "31575",
                                    "refsource": "SECUNIA",
                                    "tags": ["Permissions Required", "Third Party Advisory"]
                                }, {
                                    "url": "http://secunia.com/advisories/32241",
                                    "name": "32241",
                                    "refsource": "SECUNIA",
                                    "tags": ["Permissions Required", "Third Party Advisory"]
                                }, {
                                    "url": "http://support.avaya.com/elmodocs2/security/ASA-2008-399.htm",
                                    "name": "http://support.avaya.com/elmodocs2/security/ASA-2008-399.htm",
                                    "refsource": "CONFIRM",
                                    "tags": ["Third Party Advisory"]
                                }, {
                                    "url": "http://www.vupen.com/english/advisories/2008/2821",
                                    "name": "ADV-2008-2821",
                                    "refsource": "VUPEN",
                                    "tags": ["Broken Link"]
                                }, {
                                    "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/44747",
                                    "name": "openssh-rhel-backdoor(44747)",
                                    "refsource": "XF",
                                    "tags": []
                                }
                                ]
                            },
                            "description": {
                                "description_data": [{
                                    "lang": "en",
                                    "value": "Certain Red Hat Enterprise Linux (RHEL) 4 and 5 packages for OpenSSH, as signed in August 2008 using a legitimate Red Hat GPG key, contain an externally introduced modification (Trojan Horse) that allows the package authors to have an unknown impact.  NOTE: since the malicious packages were not distributed from any official Red Hat sources, the scope of this issue is restricted to users who may have obtained these packages through unofficial distribution points.  As of 20080827, no unofficial distributions of this software are known."
                                }
                                ]
                            }
                        },
                        "configurations": {
                            "CVE_data_version": "4.0",
                            "nodes": [{
                                "operator": "AND",
                                "children": [{
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:o:redhat:enterprise_linux:4.5.z:*:as:*:*:*:*:*",
                                        "cpe_name": []
                                    }, {
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:o:redhat:enterprise_linux:4.5.z:*:es:*:*:*:*:*",
                                        "cpe_name": []
                                    }, {
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:o:redhat:enterprise_linux:5.0:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }, {
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:o:redhat:enterprise_linux_desktop:4:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }, {
                                        "vulnerable": false,
                                        "cpe23Uri": "cpe:2.3:o:redhat:enterprise_linux_desktop:5:*:client:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }, {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [{
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                        "cpe_name": []
                                    }
                                    ]
                                }
                                ],
                                "cpe_match": []
                            }
                            ]
                        },
                        "impact": {
                            "baseMetricV2": {
                                "cvssV2": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "MEDIUM",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "COMPLETE",
                                    "integrityImpact": "COMPLETE",
                                    "availabilityImpact": "COMPLETE",
                                    "baseScore": 9.3
                                },
                                "severity": "HIGH",
                                "exploitabilityScore": 8.6,
                                "impactScore": 10,
                                "obtainAllPrivilege": false,
                                "obtainUserPrivilege": false,
                                "obtainOtherPrivilege": false,
                                "userInteractionRequired": true
                            }
                        },
                        "publishedDate": "2008-08-27T20:41Z",
                        "lastModifiedDate": "2017-08-08T01:32Z"
                    }
                    ]
                }
            }
        }, {
            "serviceName": "nginx",
            "CVEData": {
                "resultsPerPage": 0,
                "startIndex": 0,
                "totalResults": 0,
                "result": {
                    "CVE_data_type": "CVE",
                    "CVE_data_format": "MITRE",
                    "CVE_data_version": "4.0",
                    "CVE_data_timestamp": "2023-04-01T03:36Z",
                    "CVE_Items": []
                }
            }
        }
        ]
    }]

    // TODO: Parse results and return new object with only:
    // - address
    // - CVEData.totalResults
    // - CVEData.result.CVE_Items.cve.CVE_data_meta.ID
    // - CVEData.result.CVE_Items.impact.baseMetricV3.cvssV3.baseScore
    // - CVEData.result.CVE_Items.cve.description.description_data (if lang == 'en') then get .value
    // -

    const mainResults = [];

    for (const items of testResults) {
        // Iterate through each IP address
        console.log('NICE: ', items.address);
        const addr = items.address ?? null;
        const cveServicesArr = [];

        for (const serviceData of items.data) {
            // Iterate through each services CVE information
            console.log('ServiceNAME: ', serviceData.serviceName);
            const cveDataArr = [];

            const serviceName = serviceData.serviceName ?? null;
            const numResults = serviceData.CVEData.totalResults ?? null;

            for (const cveItems of serviceData.CVEData.result.CVE_Items) {
                // Iterate through each CVE

                const cveID = cveItems.cve.CVE_data_meta.ID ?? null;
                let cveScore = null;
                // const cveScore = cveItems.impact.baseMetricV3.cvssV3.baseScore ?? null;
                if (cveItems.impact.baseMetricV3) {
                    cveScore = cveItems.impact.baseMetricV3.cvssV3.baseScore;
                }  else if (cveItems.impact.baseMetricV2) {
                    cveScore = cveItems.impact.baseMetricV2.cvssV2.baseScore;
                }
                const cveDesc = cveItems.cve.description.description_data[0].value ?? null;

                cveDataArr.push({
                    "cveID": cveID,
                    "cveBaseScore": cveScore,
                    "cveDesc": cveDesc
                })
            }
            // Add the service and its CVE info to the array
            cveServicesArr.push({
                "serviceName": serviceName,
                "cveTotalResults": numResults,
                "cveData": cveDataArr
            })
        }
        // Add the address with its services to the results array
        mainResults.push({
            "address": addr,
            "cveResults": cveServicesArr
        })
    }

    console.log('MAIN OUTPUT: ', JSON.stringify(mainResults));

    const CVEResult = {
        "address": "192.168.1.13",
        "cveResults": [{
            "serviceName": "OpenSSH",
            "cveTotalResults": "9",
            "cveData": [{
                "cveID": "10283091203",
                "cveBaseScore": "8",
                "cveDesc": "This is da CVE"
            }]

        }]
    };
    const CVEResultArr = [];
    return JSON.stringify(mainResults);
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