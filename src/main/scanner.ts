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

    const nmapPromise = new Promise((resolve, reject) => {
        libnmapp.scan(opts, function(err: any, report: any) {
            if (err) throw err;

            for (let item in report) {
                console.log(JSON.stringify(report[item]));
            }

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
                            console.log('Found IP: ' + addr);
                            console.log('Ports are:')
                            console.log(JSON.stringify(portsArr));
                            console.log('OS are:')
                            console.log(JSON.stringify(osArr));

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
                            console.log('reaches! !')
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
    console.log('Scanning Ports');
    // console.log('OS and Port scan time: ' + nmapscan.scanTime);
    // // TODO: Error handling
    console.log(nmapScanResult);
    return nmapScanResult;

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