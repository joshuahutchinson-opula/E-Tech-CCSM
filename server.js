const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

// Ensure data directory exists
const DATA_DIR = './data';
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Initialize data files if they don't exist
const defaultFiles = [
  'cameras.json', 'doors.json', 'servers.json', 'switches.json', 
  'tickets.json', 'audit.json', 'inbox.json', 'clients.json', 'software.json'
];
defaultFiles.forEach(file => {
  const filePath = path.join(DATA_DIR, file);
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, '[]');
  }
});

// ============================================================
// ── HELPERS ──
// ============================================================

function readData(file) {
  try {
    const filePath = path.join(DATA_DIR, `${file}.json`);
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, '[]');
      return [];
    }
    const data = fs.readFileSync(filePath, 'utf8');
    return data ? JSON.parse(data) : [];
  } catch (error) {
    console.error(`Error reading ${file}:`, error);
    return [];
  }
}

function writeData(file, data) {
  try {
    const filePath = path.join(DATA_DIR, `${file}.json`);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error(`Error writing ${file}:`, error);
    return false;
  }
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

// ============================================================
// ── SEED DEFAULT DATA ──
// ============================================================

function getDefaultCameras() {
  return [
    {name: "HM3 PTZ", zone: "HIGH MAST", status: "Offline", comments: "Defective - POE added, camera shows signs of being defective", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 2", ip_address: "172.17.102.218", mac_address: "00-04-7D-27-9F-CF", resolution: "", warranty_expiry: ""},
    {name: "HM4 PTZ", zone: "HIGH MAST", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.102.219", mac_address: "00-04-7D-27-9F-FF", resolution: "", warranty_expiry: ""},
    {name: "HM5 PTZ", zone: "HIGH MAST", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 5", ip_address: "172.17.102.223", mac_address: "00-04-7D-27-A0-03", resolution: "", warranty_expiry: ""},
    {name: "HM5", zone: "HIGH MAST", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.102.222", mac_address: "00-18-85-2F-E7-97", resolution: "", warranty_expiry: ""},
    {name: "HM8", zone: "HIGH MAST", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.102.221", mac_address: "00-04-7D-27-9F-C9", resolution: "", warranty_expiry: ""},
    {name: "HM8 PTZ", zone: "HIGH MAST", status: "Online", comments: "", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HM10 PTZ", zone: "HIGH MAST", status: "Online", comments: "Camera is reconfigured, had default IP", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.102.224", mac_address: "00-04-7D-27-9F-C8", resolution: "", warranty_expiry: ""},
    {name: "HM11 PTZ", zone: "HIGH MAST", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.102.225", mac_address: "00-04-7D-27-9F-F0", resolution: "", warranty_expiry: ""},
    {name: "HM14 PTZ", zone: "HIGH MAST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HM14 PTZ 2", zone: "HIGH MAST", status: "Online", comments: "Will be added genetec (172.17.103.200)", model: "", manufacturer: "", archiver: "", ip_address: "172.17.103.200", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HM23", zone: "HIGH MAST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HM23 PTZ", zone: "HIGH MAST", status: "Offline", comments: "Defective - cables corroded, overheating", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.102.200", mac_address: "00-04-7D-27-9F-D2", resolution: "", warranty_expiry: ""},
    {name: "HM24A", zone: "HIGH MAST", status: "Offline", comments: "No Fibre link", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HM24A PTZ", zone: "HIGH MAST", status: "Offline", comments: "No Fibre link due to HM26 being down", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HM28 PTZ", zone: "HIGH MAST", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.102.202", mac_address: "00-04-7D-27-9F-D4", resolution: "", warranty_expiry: ""},
    {name: "Manager Car Park Dome", zone: "HIGH MAST", status: "Online", comments: "Camera lens damaged", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Manager Car Park PTZ", zone: "HIGH MAST", status: "Offline", comments: "Defective", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 4", ip_address: "172.17.102.186", mac_address: "00-04-7D-27-A0-06", resolution: "", warranty_expiry: ""},
    {name: "N25 PTZ", zone: "HIGH MAST", status: "Offline", comments: "Defective", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.102.216", mac_address: "00-04-7D-27-9F-BA", resolution: "", warranty_expiry: ""},
    {name: "N30", zone: "HIGH MAST", status: "Online", comments: "Camera damaged", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N30 PTZ", zone: "HIGH MAST", status: "Online", comments: "Reset needs to be done", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 4", ip_address: "172.17.102.210", mac_address: "00-04-7D-27-9F-EF", resolution: "", warranty_expiry: ""},
    {name: "N30 Thermal", zone: "HIGH MAST", status: "Offline", comments: "Cable replacement needed, camera taken down", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N31", zone: "HIGH MAST", status: "Online", comments: "Camera needs to be reset, POE replaced", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N31 PTZ - Context", zone: "HIGH MAST", status: "Offline", comments: "POE injector changed, needs reset, maybe defective", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N31 PTZ - Thermal", zone: "HIGH MAST", status: "Offline", comments: "POE injector changed, camera defective", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N33", zone: "HIGH MAST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N34", zone: "HIGH MAST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N34 PTZ - Context", zone: "HIGH MAST", status: "Offline", comments: "Defective", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N34 PTZ - Thermal", zone: "HIGH MAST", status: "Offline", comments: "No camera on Pole", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Visitor Car Park PTZ 1", zone: "HIGH MAST", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 2", ip_address: "172.17.102.184", mac_address: "00-04-7D-27-9F-C3", resolution: "", warranty_expiry: ""},
    {name: "Visitor Car Park PTZ 2", zone: "HIGH MAST", status: "Offline", comments: "Replacement/AXIS Q6318-LE 60HZ to be installed", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 2", ip_address: "172.17.102.185", mac_address: "00-04-7D-27-9F-E2", resolution: "", warranty_expiry: ""},
    {name: "N Fence", zone: "NORTH TERMINAL PERIMETER", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "East West Corner Perimeter Rest Bay", zone: "NORTH TERMINAL PERIMETER", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Terminal NW Corner", zone: "NORTH TERMINAL PERIMETER", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "North South Corner Rest Bay", zone: "NORTH TERMINAL PERIMETER", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "PPE Store Perim N", zone: "NORTH TERMINAL PERIMETER", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "PPE Store Perim PTZ", zone: "NORTH TERMINAL PERIMETER", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.102.203", mac_address: "00-04-7D-27-9F-C1", resolution: "", warranty_expiry: ""},
    {name: "PPE Store Perim S", zone: "NORTH TERMINAL PERIMETER", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Wharfage Perim", zone: "NORTH TERMINAL PERIMETER", status: "Offline", comments: "Replacement needed", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Wharfage Perim N Exit Gate PTZ", zone: "NORTH TERMINAL PERIMETER", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.102.183", mac_address: "00-04-7D-27-9F-FA", resolution: "", warranty_expiry: ""},
    {name: "Refueling N KWC Perim Thermal", zone: "NORTH TERMINAL THERMAL", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Fence 1 (W) Thermal", zone: "NORTH TERMINAL THERMAL", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Fence 2 (E) Thermal", zone: "NORTH TERMINAL THERMAL", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Fence 3 (W) Thermal", zone: "NORTH TERMINAL THERMAL", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Fence Stripping Warehouse Thermal", zone: "NORTH TERMINAL THERMAL", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "PPE Perim N Thermal", zone: "NORTH TERMINAL THERMAL", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "PPE Perim S Thermal", zone: "NORTH TERMINAL THERMAL", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Perim Berth 9 Area Thermal", zone: "NORTH TERMINAL THERMAL", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W Perim Berth 9 Area Thermal", zone: "NORTH TERMINAL THERMAL", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "ATM Walkway", zone: "ADMIN/HR", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Board N Ceo Secretary", zone: "ADMIN/HR", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Executive 2nd Fl Exit Stair Lower Case", zone: "ADMIN/HR", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Executive 2nd Fl Exit Stair Top Case", zone: "ADMIN/HR", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HR Meeting Rm Passage", zone: "ADMIN/HR", status: "Online", comments: "Camera refocused", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HR Waiting Area", zone: "ADMIN/HR", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Lobby HR", zone: "ADMIN/HR", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Meeting RM Passage", zone: "ADMIN/HR", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Payroll Walkway", zone: "ADMIN/HR", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Planning Main Entry", zone: "ADMIN/HR", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Procurement Passage", zone: "ADMIN/HR", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Bathroom Passage 1", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Bathroom Passage 2", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Battery Shop", zone: "ENGINEERING", status: "Online", comments: "Lift Required", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Data Center A", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Data Center B Unit", zone: "ENGINEERING", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 1", ip_address: "172.17.103.108", mac_address: "00-18-85-30-A2-14", resolution: "", warranty_expiry: ""},
    {name: "Eng Rear Passage", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Eng Workshop 3", zone: "ENGINEERING", status: "Online", comments: "Lift Required", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Engineering East Stair", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Engineering Entry", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Engineering Entry Passage", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Engineering Gym", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Engineering Lunch Room", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Engineering Lunch RM Kitchen", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Engineering Rear Passage", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Engineering Stationary Passage", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Engineering West Stair", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "F Changing Room Exit Passage", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "IT Entry", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "IT Exit", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "IT Stairwell", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Training Room East", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Training Room West", zone: "ENGINEERING", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Tyre Shop", zone: "ENGINEERING", status: "Online", comments: "Lift Required", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HR Tower 1 PTZ", zone: "HR TOWERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HR Tower 2 PTZ", zone: "HR TOWERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Canteen East Entry", zone: "WELFARE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Canteen West Entry", zone: "WELFARE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Cashier / Service Counter Canteen", zone: "WELFARE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Dining Area 1 Canteen", zone: "WELFARE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Dining Area 2 Canteen", zone: "WELFARE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Welfare Passage", zone: "WELFARE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Engineering Stationary Passage", zone: "PPE STORE/INVENTORY", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "PPE N Stationary Entry/Exit Gate", zone: "PPE STORE/INVENTORY", status: "Online", comments: "Lift Required", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "PPE Store Entrance", zone: "PPE STORE/INVENTORY", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "PPE Store Inventory", zone: "PPE STORE/INVENTORY", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Store Entrance", zone: "PPE STORE/INVENTORY", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Store Rear Entry N Passage", zone: "PPE STORE/INVENTORY", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Store Warehouse 3", zone: "PPE STORE/INVENTORY", status: "Online", comments: "Lift Required", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Store Warehouse", zone: "PPE STORE/INVENTORY", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Cashier Window 1 Wharfage", zone: "WHARFAGE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Cashier Window 2 Wharfage", zone: "WHARFAGE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Cashier Window 3 Wharfage", zone: "WHARFAGE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Customer / Broker Entry", zone: "WHARFAGE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Customer/Broker Lobby NW Corner", zone: "WHARFAGE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Customer/Broker Lobby SE Corner", zone: "WHARFAGE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Wharfage Office Cashier 1", zone: "WHARFAGE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Wharfage Office Cashier 2", zone: "WHARFAGE", status: "Online", comments: "Dome needs to be changed", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Wharfage Office Cashier 3", zone: "WHARFAGE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Wharfage Office Cashier Emergency Door", zone: "WHARFAGE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Wharfage Office NW Corner", zone: "WHARFAGE", status: "Online", comments: "Ceiling tile replaced", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Wharfage Storage Area/Safe", zone: "WHARFAGE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Wharfage Staff Entry Office", zone: "WHARFAGE", status: "Online", comments: "Ceiling tile replaced", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Tollgate Entry LPR - LPR", zone: "LPR SYSTEM UNITS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Tollgate Exit LPR", zone: "LPR SYSTEM UNITS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Entry 1 LPR", zone: "LPR SYSTEM UNITS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Entry 2 LPR", zone: "LPR SYSTEM UNITS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Entry LPR 3", zone: "LPR SYSTEM UNITS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Entry LPR 4", zone: "LPR SYSTEM UNITS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Exit LPR", zone: "LPR SYSTEM UNITS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Toll Booth Exit PTZ", zone: "PORT ENTRY EXIT", status: "Online", comments: "Lift required", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Toll Gate Entry PTZ", zone: "PORT ENTRY EXIT", status: "Online", comments: "Lift required", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Car Park 3", zone: "PORT ENTRY EXIT", status: "Online", comments: "Lift required", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Exit Gate", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Gate Office E Side Outside", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "KFTL Port Main Entry Exit", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "MainEntry/Exit Security Walkway", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Toll Gate Entry", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Toll Gate Exit", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Tollgate Entry LPR - Context", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Tollgate Exit LPR - Context", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Entry 1", zone: "PORT ENTRY EXIT", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Entry 1 LPR Context", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Entry 2", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck entry 2 LPR - Context", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Entry LPR 3 - Context", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Entry LPR 4 - Context", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Exit", zone: "PORT ENTRY EXIT", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Exit LPR - Context", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Truck Guard House Exit", zone: "PORT ENTRY EXIT", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Broker Parking area", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Car Park 1", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Car Park 2", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Car Park 4", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Car Park 5", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Car Park 6", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Gate Office Eastern Side", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Monitoring Room 1", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Monitoring Room 2", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Productions Turn Style", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Radio Room", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Recreation Area Rest Bay", zone: "OTHERS", status: "Online", comments: "Camera replaced - RESOLVED", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Registry Entry Passage", zone: "OTHERS", status: "Offline", comments: "Offline", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Registry Office Passage Rear", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Registry Passage to Warehouse", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Rest Bay Turn Style", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Security Dept West Side 1", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Security Dept West Side 2", zone: "OTHERS", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "HR Building Rear Walkway", zone: "OTHERS", status: "Offline", comments: "Offline", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane K", zone: "CRANES", status: "Online", comments: "Crane is offline due to Maintenance", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane M", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane S", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane A", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane B", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane N", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane O", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane P", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane Q", zone: "CRANES", status: "Online", comments: "Crane is offline due to Maintenance", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane C Under", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane D Under", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane C Backreach", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane T", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane Y", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane U", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane R", zone: "CRANES", status: "Online", comments: "Switch replaced with Blind Spot switch", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane Z", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane L", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Crane V", zone: "CRANES", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Vet Waiting Area", zone: "VET OFFICE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Vet Office 2 Window", zone: "VET OFFICE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Vet Office entry Walkway", zone: "VET OFFICE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Scanning Area 1", zone: "VET OFFICE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Scanning Area 2", zone: "VET OFFICE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Vet Office 1", zone: "VET OFFICE", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W1", zone: "WEST", status: "Online", comments: "RESOLVED - Network connection come from W2", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.103.155", mac_address: "00-18-85-30-A2-10", resolution: "", warranty_expiry: ""},
    {name: "W2", zone: "WEST", status: "Online", comments: "RESOLVED - Power Supply for switch replaced", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W3", zone: "WEST", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.102.230", mac_address: "00-18-85-2F-E7-9C", resolution: "", warranty_expiry: ""},
    {name: "W4", zone: "WEST", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.102.232", mac_address: "00-18-85-30-A2-1A", resolution: "", warranty_expiry: ""},
    {name: "W5", zone: "WEST", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.102.228", mac_address: "00-18-85-30-A2-0F", resolution: "", warranty_expiry: ""},
    {name: "W6", zone: "WEST", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.102.233", mac_address: "00-18-85-2F-0B-A6", resolution: "", warranty_expiry: ""},
    {name: "W7", zone: "WEST", status: "Online", comments: "Ends recrimped. Cable is water logged, water seeping through.", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.102.234", mac_address: "00-18-85-30-A2-1F", resolution: "", warranty_expiry: ""},
    {name: "W8", zone: "WEST", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 4", ip_address: "172.17.102.235", mac_address: "00-18-85-30-A2-17", resolution: "", warranty_expiry: ""},
    {name: "W9", zone: "WEST", status: "Online", comments: "Firmware Update Done POE injector added", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 4", ip_address: "172.17.102.236", mac_address: "00-18-85-30-A2-2C", resolution: "", warranty_expiry: ""},
    {name: "W10", zone: "WEST", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 4", ip_address: "172.17.102.231", mac_address: "00-18-85-30-A2-1D", resolution: "", warranty_expiry: ""},
    {name: "W11", zone: "WEST", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.102.239", mac_address: "00-18-85-30-A2-52", resolution: "", warranty_expiry: ""},
    {name: "W12", zone: "WEST", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.102.240", mac_address: "00-18-85-30-A2-4C", resolution: "", warranty_expiry: ""},
    {name: "W13", zone: "WEST", status: "Offline", comments: "Damaged by VTR, cable needs to be replaced", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.102.241", mac_address: "00-18-85-30-A2-29", resolution: "", warranty_expiry: ""},
    {name: "W16", zone: "WEST", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.102.242", mac_address: "00-18-85-30-A2-4F", resolution: "", warranty_expiry: ""},
    {name: "WB11", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W Perim 6 Adjacent W9", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W1 PTZ", zone: "WEST", status: "Online", comments: "RESOLVED - Network connection from W2", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W2 PTZ", zone: "WEST", status: "Online", comments: "RESOLVED - Power Supply for switch replaced", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W3 PTZ", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W4 PTZ", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W5 PTZ", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W6 PTZ", zone: "WEST", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 2", ip_address: "172.17.102.248", mac_address: "00-04-7D-27-9F-ED", resolution: "", warranty_expiry: ""},
    {name: "W7 PTZ", zone: "WEST", status: "Online", comments: "Ends recrimped. Cable is water logged, water seeping through.Camera is operational", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W8 PTZ", zone: "WEST", status: "Offline", comments: "Firmware Update Done POE injector added,Unable to pan, camera has blank screen is defective", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W9 PTZ", zone: "WEST", status: "Online", comments: "Firmware Update Done POE injector added", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W11 PTZ", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W12 PTZ", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W13 PTZ", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W16 PTZ", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "WB1 PTZ - Stream 1", zone: "WEST", status: "Online", comments: "RESOLVED - Replacement done P14767-LE. Camera defective replaced June 17th", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W Perim PTZ", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "WB11 PTZ", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "WB1 PTZ", zone: "WEST", status: "Online", comments: "RESOLVED - Camera replaced by P1467 Bullet", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W Perim 1 Thermal Adjacent to W4", zone: "WEST", status: "Offline", comments: "No camera on pole", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W Perim 2 Thermal Adjacent to W7", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W Perim 3 Thermal Adjacent to W7", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W Perim 4 Thermal Adjacent to W9", zone: "WEST", status: "Offline", comments: "No camera on pole", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "W Perim 5 Thermal Adjacent to W4", zone: "WEST", status: "Offline", comments: "No camera on pole", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "WB11 Thermal", zone: "WEST", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A1", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A2", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A3", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A4", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A5", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A6", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A7", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A8", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A9", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A10", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A11", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A12", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A13 (197)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A13 (192)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A14", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 3", ip_address: "172.17.103.5", mac_address: "00-18-85-2F-E7-88", resolution: "", warranty_expiry: ""},
    {name: "A1 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.103.30", mac_address: "00-04-7D-27-9F-CB", resolution: "", warranty_expiry: ""},
    {name: "A2 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 5", ip_address: "172.17.103.144", mac_address: "00-04-7D-27-9F-C4", resolution: "", warranty_expiry: ""},
    {name: "A3 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.103.32", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A4 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.103.33", mac_address: "00-04-7D-27-A0-00", resolution: "", warranty_expiry: ""},
    {name: "A5 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 4", ip_address: "172.17.103.34", mac_address: "00-04-7D-27-9F-C6", resolution: "", warranty_expiry: ""},
    {name: "A6 PTZ", zone: "SOUTH", status: "Online", comments: "Camera on default, reconfigured", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 4", ip_address: "172.17.103.35", mac_address: "00-04-7D-27-9F-FC", resolution: "", warranty_expiry: ""},
    {name: "A7 PTZ", zone: "SOUTH", status: "Offline", comments: "Camera defective", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 4", ip_address: "172.17.103.36", mac_address: "00-04-7D-27-9F-CA", resolution: "", warranty_expiry: ""},
    {name: "A8 PTZ", zone: "SOUTH", status: "Offline", comments: "Camera defective", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 4", ip_address: "172.17.103.37", mac_address: "00-04-7D-27-9F-F9", resolution: "", warranty_expiry: ""},
    {name: "A9 PTZ Context Stream", zone: "SOUTH", status: "Offline", comments: "Camera defective", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A10 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.103.39", mac_address: "00-04-7D-27-9F-F3", resolution: "", warranty_expiry: ""},
    {name: "A11 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.103.40", mac_address: "00-04-7D-27-A0-0A", resolution: "", warranty_expiry: ""},
    {name: "A12 PTZ", zone: "SOUTH", status: "Online", comments: "Body adjusted", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.41", mac_address: "00-04-7D-27-9F-FD", resolution: "", warranty_expiry: ""},
    {name: "A13 PTZ Stream 1", zone: "SOUTH", status: "Offline", comments: "Camera defective", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A13 PTZ Thermal", zone: "SOUTH", status: "Offline", comments: "cable tested good, cable ends are good, no POE light present. Camera defective", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A9 PTZ Thermal", zone: "SOUTH", status: "Offline", comments: "cable tested good, cable ends are good, no POE light present. Camera defective", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A13 Strad Park", zone: "SOUTH", status: "Online", comments: "Adjusted, Steel Straps replaced", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "A14 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B1 (216)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B1 (363)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B2", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B3", zone: "SOUTH", status: "Online", comments: "RESOLVED - weatherproof box falling off pole, needs attention", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B5 (209)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B5 (212)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B5 (217)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B6 (218)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B6 (211)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B7 (213)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B7 (215)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B8", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 4", ip_address: "172.17.103.54", mac_address: "00-18-85-2F-E7-93", resolution: "", warranty_expiry: ""},
    {name: "B9", zone: "SOUTH", status: "Online", comments: "RESOLVED - Cable replaced(5/6/2026), Weather proof box needs to be attached correctly", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 1", ip_address: "172.17.103.55", mac_address: "00-18-85-2F-E7-C2", resolution: "", warranty_expiry: ""},
    {name: "B10", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "B11", zone: "SOUTH", status: "Online", comments: "RESOLVED - Cable was replaced (6/24/2026)", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.103.57", mac_address: "00-18-85-30-A2-56", resolution: "", warranty_expiry: ""},
    {name: "B12", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.103.58", mac_address: "00-18-85-2F-E7-95", resolution: "", warranty_expiry: ""},
    {name: "B13", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 2", ip_address: "172.17.103.59", mac_address: "00-18-85-2F-E7-ED", resolution: "", warranty_expiry: ""},
    {name: "B14", zone: "SOUTH", status: "Online", comments: "Obstacles, unable to clean", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.7", mac_address: "00-18-85-2F-E7-98", resolution: "", warranty_expiry: ""},
    {name: "B1 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.60", mac_address: "00-04-7D-27-9F-F6", resolution: "", warranty_expiry: ""},
    {name: "B2 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.61", mac_address: "00-04-7D-27-9F-F7", resolution: "", warranty_expiry: ""},
    {name: "B3 PTZ", zone: "SOUTH", status: "Online", comments: "RESOLVED - CONFIRMED ONLINE June 8th", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.103.46", mac_address: "00-18-85-30-A2-3D", resolution: "", warranty_expiry: ""},
    {name: "B5 PTZ", zone: "SOUTH", status: "Offline", comments: "Only Pole mount present", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.63", mac_address: "00-04-7D-27-9F-EB", resolution: "", warranty_expiry: ""},
    {name: "B6 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.64", mac_address: "00-04-7D-27-9F-F8", resolution: "", warranty_expiry: ""},
    {name: "B7 PTZ", zone: "SOUTH", status: "Online", comments: "RESOLVED - REPLACED CAMERA on 5/6/2026", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 1", ip_address: "172.17.103.52", mac_address: "00-18-85-30-A2-32", resolution: "", warranty_expiry: ""},
    {name: "B8 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.66", mac_address: "00-04-7D-27-9F-BD", resolution: "", warranty_expiry: ""},
    {name: "B9 PTZ", zone: "SOUTH", status: "Online", comments: "RESOLVED - Cable Replacement done", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.67", mac_address: "00-04-7D-27-9F-C2", resolution: "", warranty_expiry: ""},
    {name: "B10 PTZ", zone: "SOUTH", status: "Online", comments: "POE replaced with SW perim PTZ POE", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.68", mac_address: "00-04-7D-27-A0-02", resolution: "", warranty_expiry: ""},
    {name: "B11 PTZ", zone: "SOUTH", status: "Online", comments: "RESOLVED - Cable was replaced (6/24/2026)", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.69", mac_address: "00-04-7D-27-F4-30", resolution: "", warranty_expiry: ""},
    {name: "B12 PTZ", zone: "SOUTH", status: "Online", comments: "Camera was reset to default IP adjustments made.", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.70", mac_address: "00-04-7D-27-9F-F5", resolution: "", warranty_expiry: ""},
    {name: "B14 PTZ", zone: "SOUTH", status: "Online", comments: "Obstacles, unable to clean", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "C1", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.71", mac_address: "00-18-85-30-A2-40", resolution: "", warranty_expiry: ""},
    {name: "C2", zone: "SOUTH", status: "Online", comments: "Obstacles, unable to clean.", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.72", mac_address: "00-18-85-30-A2-51", resolution: "", warranty_expiry: ""},
    {name: "C4", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.73", mac_address: "00-18-85-2F-E7-8E", resolution: "", warranty_expiry: ""},
    {name: "C5 (236)", zone: "SOUTH", status: "Offline", comments: "Camera Defective", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.75", mac_address: "00-18-85-2F-E7-B8", resolution: "", warranty_expiry: ""},
    {name: "C5 (237)", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.74", mac_address: "00-18-85-2F-E7-A4", resolution: "", warranty_expiry: ""},
    {name: "C9 (285)", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.77", mac_address: "00-18-85-30-A2-2D", resolution: "", warranty_expiry: ""},
    {name: "C9 (286)", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "C11", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.78", mac_address: "00-18-85-30-A2-28", resolution: "", warranty_expiry: ""},
    {name: "C12 (239)", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.79", mac_address: "00-18-85-2F-E7-89", resolution: "", warranty_expiry: ""},
    {name: "C12 (240)", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.80", mac_address: "00-18-85-30-A2-21", resolution: "", warranty_expiry: ""},
    {name: "C1 PTZ (243)", zone: "SOUTH", status: "Offline", comments: "Camera is defective", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 4", ip_address: "172.17.103.81", mac_address: "00-04-7D-27-9F-F2", resolution: "", warranty_expiry: ""},
    {name: "C2 PTZ", zone: "SOUTH", status: "Online", comments: "Obstacles, unable to clean.", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 5", ip_address: "172.17.103.82", mac_address: "00-04-7D-27-9F-D0", resolution: "", warranty_expiry: ""},
    {name: "C4 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.103.83", mac_address: "00-04-7D-27-F4-32", resolution: "", warranty_expiry: ""},
    {name: "C9 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.143", mac_address: "00-04-7D-27-9F-D3", resolution: "", warranty_expiry: ""},
    {name: "C11 PTZ", zone: "SOUTH", status: "Offline", comments: "Only Pole mount present", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.103.85", mac_address: "00-04-7D-27-F4-2A", resolution: "", warranty_expiry: ""},
    {name: "C12 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D1", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.87", mac_address: "00-18-85-30-A2-24", resolution: "", warranty_expiry: ""},
    {name: "D2", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.88", mac_address: "00-18-85-30-A2-1B", resolution: "", warranty_expiry: ""},
    {name: "D4", zone: "SOUTH", status: "Online", comments: "RESOLVED - CONFIRMED ONLINE June 8th", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.89", mac_address: "00-18-85-30-A2-2A", resolution: "", warranty_expiry: ""},
    {name: "D5", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.90", mac_address: "00-18-85-2F-E7-FF", resolution: "", warranty_expiry: ""},
    {name: "D6", zone: "SOUTH", status: "Online", comments: "RESOLVED - Cable Replacement done", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 4", ip_address: "172.17.103.106", mac_address: "00-18-85-2F-0B-93", resolution: "", warranty_expiry: ""},
    {name: "D7", zone: "SOUTH", status: "Online", comments: "Working", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.92", mac_address: "00-18-85-30-A2-26", resolution: "", warranty_expiry: ""},
    {name: "D8", zone: "SOUTH", status: "Online", comments: "RESOLVED - No Fibre Cable Replacement done", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 5", ip_address: "172.17.103.93", mac_address: "00-18-85-30-A2-11", resolution: "", warranty_expiry: ""},
    {name: "D11", zone: "SOUTH", status: "Offline", comments: "No camera on Pole", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D12", zone: "SOUTH", status: "Online", comments: "Obstacles, unable to clean.", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.105", mac_address: "00-04-7D-27-9F-BE", resolution: "", warranty_expiry: ""},
    {name: "D1 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D2 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D4 PTZ", zone: "SOUTH", status: "Online", comments: "RESOLVED - CONFIRMED ONLINE June 8th", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 2", ip_address: "172.17.103.99", mac_address: "00-04-7D-27-A0-05", resolution: "", warranty_expiry: ""},
    {name: "D5 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 2", ip_address: "172.17.103.100", mac_address: "00-04-7D-27-F4-2F", resolution: "", warranty_expiry: ""},
    {name: "D6 PTZ", zone: "SOUTH", status: "Online", comments: "RESOLVED - Cable replacement done", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D7 PTZ", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D8 PTZ", zone: "SOUTH", status: "Online", comments: "RESOLVED - Cable Replacement done (16/5/2026)", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D10 PTZ", zone: "SOUTH", status: "Online", comments: "Obstacles, unable to clean.", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 5", ip_address: "172.17.103.104", mac_address: "00-04-7D-27-DD-C2", resolution: "", warranty_expiry: ""},
    {name: "D12 PTZ", zone: "SOUTH", status: "Online", comments: "Camera moved to Archiver 3", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 3", ip_address: "172.17.103.105", mac_address: "00-04-7D-27-9F-BE", resolution: "", warranty_expiry: ""},
    {name: "E 2", zone: "SOUTH", status: "Online", comments: "Analytics configured", model: "5.0C-H5A-DP2", manufacturer: "Avigilon", archiver: "Archiver 3", ip_address: "172.17.103.11", mac_address: "00-18-85-2F-E7-92", resolution: "", warranty_expiry: ""},
    {name: "E2 PTZ", zone: "SOUTH", status: "Online", comments: "RESOLVED - Replaced with B7 old removed camera (5/7/2026)", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D4 Thermal", zone: "SOUTH", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D6 Perim Fence Thermal 2", zone: "SOUTH", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D6 Perim Fence Thermal", zone: "SOUTH", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D8 Thermal", zone: "SOUTH", status: "Offline", comments: "No fibre link", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D8 Thermal 2", zone: "SOUTH", status: "Offline", comments: "No fibre link", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "D11 Thermal", zone: "SOUTH", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "MEZ SE Corner Thermal", zone: "SOUTH", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "South Perim 2 Thermal", zone: "SOUTH", status: "Online", comments: "Analytics Applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "South Perim Thermal", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "South East Tower Thermal", zone: "SOUTH", status: "Online", comments: "RESOLVED - REPLACED on 6/23/2026", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "MEZ SW Corner", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "MEZ SE Corner PTZ", zone: "SOUTH", status: "Online", comments: "Online POE needed.", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "South Perim PTZ - Context", zone: "SOUTH", status: "Online", comments: "Working", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "South Perim PTZ", zone: "SOUTH", status: "Offline", comments: "Camera defective", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 1", ip_address: "172.17.103.86", mac_address: "00-04-7D-27-9F-CC", resolution: "", warranty_expiry: ""},
    {name: "South Perim PTZ Thermal", zone: "SOUTH", status: "Offline", comments: "Camera defective", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "SE Tower PTZ - Thermal", zone: "SOUTH", status: "Online", comments: "Needs injector", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay T", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Bay 2", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Bay 5", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Bay 7", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Bay 8", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Obstacle blocking area", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Bay 9", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Bay 10", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Bay 11", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Bay 12", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Platform 1 Stripping", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "N Platform 2 Stripping", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "NE Corner Stripping", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "NW Corner Stripping", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Rear Entry/ Exit", zone: "JIEIC WAREHOUSE", status: "Online", comments: "RESOLVED - Camera replaced 6/20/2026", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay AB", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay CD", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay EF", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay G", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay HI", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay J", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay KL", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay M", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay NO", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay PQ", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay RS", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "S Bay U", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "SE Corner Stripping", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Security Station N Pedestrian Gate", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "SW Corner Perimeter 1 Stripping", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "SW Corner Perimeter 2 Stripping", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "SW Corner Stripping", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Warehouse Passage", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Warehouse Walkway N Parking", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Analytics applied", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "SW Corner Perim PTZ", zone: "JIEIC WAREHOUSE", status: "Online", comments: "RESOLVED - REPLACED (6/29/2026)", model: "P2820-ESR", manufacturer: "pelco", archiver: "Archiver 4", ip_address: "172.17.102.155", mac_address: "00-04-7D-27-A0-04", resolution: "", warranty_expiry: ""},
    {name: "Warehouse Central PTZ 2", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""},
    {name: "Warehouse Central PTZ", zone: "JIEIC WAREHOUSE", status: "Online", comments: "Switch rebooted and port bandwidth adjusted", model: "", manufacturer: "", archiver: "", ip_address: "", mac_address: "", resolution: "", warranty_expiry: ""}
  ];
  return defaultCameras;
}

function seedDefaultData() {
  const camerasFile = path.join(DATA_DIR, 'cameras.json');
  const clientsFile = path.join(DATA_DIR, 'clients.json');
  
  // Seed cameras if empty
  try {
    const data = fs.readFileSync(camerasFile, 'utf8');
    const parsed = JSON.parse(data);
    if (parsed.length === 0) {
      const defaultCameras = getDefaultCameras();
      fs.writeFileSync(camerasFile, JSON.stringify(defaultCameras, null, 2));
      console.log('✅ Seeded ' + defaultCameras.length + ' default cameras');
    }
  } catch (error) {
    console.error('Error seeding cameras:', error);
  }
  
  // Seed clients if empty
  try {
    const data = fs.readFileSync(clientsFile, 'utf8');
    const parsed = JSON.parse(data);
    if (parsed.length === 0) {
      const defaultClients = ['KFTL', 'KWL', 'Lasco', 'Nestle', 'NIDS', 'Nutrien', 'Fidelity Motors'];
      fs.writeFileSync(clientsFile, JSON.stringify(defaultClients, null, 2));
      console.log('✅ Seeded ' + defaultClients.length + ' default clients');
    }
  } catch (error) {
    console.error('Error seeding clients:', error);
  }
}

// Run seed on startup
seedDefaultData();

// ============================================================
// ── DEVICE DETECTION ──
// ============================================================

const isMobileDevice = (userAgent) => {
  return /Android|iPhone|iPod|BlackBerry|Opera Mini|IEMobile|webOS|Windows Phone|iPad|Tablet|Silk|PlayBook/i.test(userAgent);
};

app.get('/', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const forceMobile = req.query.mobile === 'true';
  const forceDesktop = req.query.desktop === 'true';
  
  let serveMobile = isMobileDevice(userAgent);
  if (forceMobile) serveMobile = true;
  if (forceDesktop) serveMobile = false;
  
  const file = serveMobile ? 'field-app.html' : 'index.html';
  if (fs.existsSync(path.join(__dirname, file))) {
    res.sendFile(path.join(__dirname, file));
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/field', (req, res) => {
  res.sendFile(path.join(__dirname, 'field-app.html'));
});

// ============================================================
// ── API ROUTES ──
// ============================================================

// Auth
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === 'admin' && password === 'admin123') {
    return res.json({ 
      success: true, 
      token: 'admin-token-' + Date.now(), 
      user: { 
        username: 'admin', 
        role: 'Administrator', 
        isAdmin: true,
        client: null
      } 
    });
  }
  
  const techs = ['tech', 'shanice', 'shavine', 'marvin', 'ackeem'];
  if (techs.includes(username.toLowerCase()) && password === 'tech123') {
    return res.json({ 
      success: true, 
      token: 'tech-token-' + Date.now(), 
      user: { 
        username: username, 
        role: 'Field Technician', 
        isAdmin: false,
        client: null
      } 
    });
  }
  
  const clients = ['kftl', 'kwl', 'lasco', 'nestle', 'nids', 'nutrien', 'fidelity'];
  if (clients.includes(username.toLowerCase()) && password === username.toLowerCase() + '123') {
    return res.json({ 
      success: true, 
      token: 'client-token-' + Date.now(), 
      user: { 
        username: username, 
        role: 'Client User', 
        isAdmin: false,
        client: username.toLowerCase()
      } 
    });
  }
  
  res.status(401).json({ success: false, message: 'Invalid credentials' });
});

app.post('/api/auth/microsoft', (req, res) => {
  res.json({ 
    success: true,
    access_token: 'mock-token-' + Date.now(),
    user: { username: 'microsoft-user', role: 'User', isAdmin: false }
  });
});

// GET endpoints
app.get('/api/cameras', (req, res) => {
  const data = readData('cameras');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/doors', (req, res) => {
  const data = readData('doors');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/servers', (req, res) => {
  const data = readData('servers');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/switches', (req, res) => {
  const data = readData('switches');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/software', (req, res) => {
  const data = readData('software');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/clients', (req, res) => {
  const data = readData('clients');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/tickets', (req, res) => {
  const { status, priority, assigned, client, limit = 100 } = req.query;
  let data = readData('tickets');
  
  if (status) data = data.filter(t => t.status === status);
  if (priority) data = data.filter(t => t.priority === priority);
  if (assigned) data = data.filter(t => t.assigned === assigned);
  if (client) data = data.filter(t => t.client === client);
  
  data.sort((a, b) => new Date(b.received || b.created) - new Date(a.received || a.created));
  if (limit > 0) data = data.slice(0, parseInt(limit));
  
  res.json({ success: true, data, count: data.length, total: readData('tickets').length });
});

app.get('/api/audit', (req, res) => {
  const { limit = 100, user, action } = req.query;
  let data = readData('audit');
  
  if (user) data = data.filter(a => a.user === user);
  if (action) data = data.filter(a => a.action === action);
  
  data.sort((a, b) => new Date(b.time) - new Date(a.time));
  if (limit > 0) data = data.slice(0, parseInt(limit));
  
  res.json({ success: true, data, count: data.length });
});

app.get('/api/inbox', (req, res) => {
  const data = readData('inbox');
  res.json({ success: true, data, count: data.length });
});

// GET single items
app.get('/api/cameras/:id', (req, res) => {
  const data = readData('cameras');
  const item = data.find(c => c.id === req.params.id);
  if (item) {
    res.json({ success: true, data: item });
  } else {
    res.status(404).json({ success: false, message: 'Item not found' });
  }
});

app.get('/api/tickets/:id', (req, res) => {
  const data = readData('tickets');
  const item = data.find(t => t.id === req.params.id);
  if (item) {
    res.json({ success: true, data: item });
  } else {
    res.status(404).json({ success: false, message: 'Ticket not found' });
  }
});

// POST endpoints
app.post('/api/cameras', (req, res) => {
  try {
    const data = readData('cameras');
    const newItem = { id: generateId(), ...req.body, created: new Date().toISOString() };
    data.push(newItem);
    writeData('cameras', data);
    res.status(201).json({ success: true, data: newItem });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/doors', (req, res) => {
  try {
    const data = readData('doors');
    const newItem = { id: generateId(), ...req.body, created: new Date().toISOString() };
    data.push(newItem);
    writeData('doors', data);
    res.status(201).json({ success: true, data: newItem });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/tickets', (req, res) => {
  try {
    const data = readData('tickets');
    const newTicket = { 
      id: 'SR-' + String(Math.floor(Math.random() * 9000) + 1000),
      ...req.body,
      created: new Date().toISOString(),
      history: [{ time: new Date().toISOString(), msg: 'Created' }],
      attachments: []
    };
    data.push(newTicket);
    writeData('tickets', data);
    res.status(201).json({ success: true, data: newTicket });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/audit', (req, res) => {
  try {
    const data = readData('audit');
    const entry = { 
      ...req.body, 
      time: new Date().toISOString(),
      id: generateId()
    };
    data.push(entry);
    writeData('audit', data);
    res.status(201).json({ success: true, data: entry });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// PUT endpoints
app.put('/api/cameras/:id', (req, res) => {
  try {
    const data = readData('cameras');
    const index = data.findIndex(c => c.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Camera not found' });
    }
    data[index] = { ...data[index], ...req.body, updated: new Date().toISOString() };
    writeData('cameras', data);
    res.json({ success: true, data: data[index] });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/doors/:id', (req, res) => {
  try {
    const data = readData('doors');
    const index = data.findIndex(d => d.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Door not found' });
    }
    data[index] = { ...data[index], ...req.body, updated: new Date().toISOString() };
    writeData('doors', data);
    res.json({ success: true, data: data[index] });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/tickets/:id', (req, res) => {
  try {
    const data = readData('tickets');
    const index = data.findIndex(t => t.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    if (req.body.status && data[index].status !== req.body.status) {
      if (!data[index].history) data[index].history = [];
      data[index].history.push({
        time: new Date().toISOString(),
        msg: `Status → ${req.body.status}`
      });
    }
    
    data[index] = { ...data[index], ...req.body, updated: new Date().toISOString() };
    writeData('tickets', data);
    res.json({ success: true, data: data[index] });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Bulk save
app.post('/api/save/:type', (req, res) => {
  const { type } = req.params;
  const validTypes = ['cameras', 'doors', 'servers', 'switches', 'tickets', 'audit', 'inbox', 'software', 'clients'];
  
  if (!validTypes.includes(type)) {
    return res.status(400).json({ success: false, message: 'Invalid data type' });
  }
  
  try {
    writeData(type, req.body);
    res.json({ success: true, count: req.body.length });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Stats
app.get('/api/stats', (req, res) => {
  const stats = {};
  const types = ['cameras', 'doors', 'servers', 'switches', 'tickets', 'audit', 'inbox', 'software', 'clients'];
  types.forEach(type => {
    const data = readData(type);
    stats[type] = data.length;
  });
  
  const tickets = readData('tickets');
  stats.openTickets = tickets.filter(t => t.status !== 'Resolved').length;
  stats.highPriorityTickets = tickets.filter(t => t.priority === 'High' && t.status !== 'Resolved').length;
  
  res.json({ success: true, data: stats });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

// Catch-all
app.get('*', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const isMobile = isMobileDevice(userAgent);
  const file = isMobile ? 'field-app.html' : 'index.html';
  
  if (fs.existsSync(path.join(__dirname, file))) {
    res.sendFile(path.join(__dirname, file));
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

// Start
app.listen(PORT, () => {
  console.log('🚀 CAMS Server running on port ' + PORT);
  console.log('📱 Mobile users → field-app.html (auto-detected)');
  console.log('💻 Desktop users → index.html (auto-detected)');
  console.log('📌 Direct: /admin (desktop) or /field (mobile)');
  console.log('💾 Data stored in /data/ folder');
});
