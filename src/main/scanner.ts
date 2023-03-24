import {json} from "stream/consumers";

const { Worker } =  require('worker_threads');
const { networkInterfaces } = require('os');
const { promisify } = require('util');
const net = require('net');
const ping = require('ping');
const nmap = require('node-nmap');
nmap.nmapLocation = 'nmap';

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
    // let mainList: string[] = [];
    // for (let i = 0; i < devices.length; i++) {
    //     console.log('Currently at device: ' + devices[i]);
    //     mainList.push(devices[i]);
    // }
    // let testList = [
    //     '192.168.1.1',   '192.168.1.11',
    //     '192.168.1.69',  '192.168.1.103',
    //     '192.168.1.104', '192.168.1.111',
    //     '192.168.1.133', '192.168.1.161',
    //     '192.168.1.175', '192.168.1.186',
    // ];

    // console.log('DEVICES In PORT SCAN: ');
    // console.log(devices);
    // console.log(typeof devices);
    // console.log(testList)
    // console.log(typeof testList);
    // console.log(mainList)
    // console.log(typeof mainList);

    // let nmapscan = new nmap.OsAndPortScan(mainList);
    let nmapscan = new nmap.NmapScan(devices, ['-O', '-sS', '-T4']);
    // let nmapscan = new nmap.NmapScan('192.168.1.69', ['-sV']);


    const nmapPromise = new Promise((resolve, reject) => {
        nmapscan.on('complete', function (data: any) {
            console.log(JSON.stringify(data));
            // for (let i = 0; i < data.length; i++) {
            //     ipAddresses.push(data[i].ip)
            // }
            // console.log(ipAddresses);

            resolve(JSON.stringify(data));
        });

        nmapscan.on('error', function (error: any) {
            console.log('Error in the Port Scanning function: ' + error);
            reject(error);
        });
    });

    nmapscan.startScan(); // Start the nmap scan
    let nmapScanResult = await nmapPromise; // Wait for the promise to resolve
    // console.log('Scanning Ports');
    console.log('OS and Port scan time: ' + nmapscan.scanTime);
    // TODO: Error handling
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