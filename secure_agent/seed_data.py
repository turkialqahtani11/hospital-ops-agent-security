"""Synthetic hospital equipment and maintenance records.

Everything here is invented for a security lab. There is no patient data, no PHI,
no real vendor, no credential and no connection to a live hospital system.
Two tenants exist so cross-tenant leakage can be demonstrated: hosp_a and hosp_b.
"""

# asset_id, tenant_id, name, category, location, status, criticality, last_service, next_service
EQUIPMENT = [
    ("VEN-101", "hosp_a", "AeroVent X2 Ventilator", "ventilator", "ICU Bed 4", "in_service", "high", "2026-04-10", "2026-10-10"),
    ("VEN-102", "hosp_a", "AeroVent X2 Ventilator", "ventilator", "ER Bay 2", "in_service", "high", "2026-07-02", "2027-01-02"),
    ("INF-201", "hosp_a", "FlowSure 300 Infusion Pump", "infusion_pump", "Ward 3 West", "advisory", "high", "2026-06-15", "2026-12-15"),
    ("INF-202", "hosp_a", "FlowSure 300 Infusion Pump", "infusion_pump", "Ward 5 East", "in_service", "high", "2026-08-20", "2027-02-20"),
    ("DEF-301", "hosp_a", "PulseGuard Defibrillator", "defibrillator", "ER Crash Cart 1", "in_service", "high", "2026-09-01", "2026-12-01"),
    ("GEN-401", "hosp_a", "Emergency Generator 1 MVA", "generator", "Plant Room B1", "in_service", "critical", "2026-10-01", "2026-11-01"),
    ("AUT-501", "hosp_a", "Benchtop Autoclave", "sterilizer", "Dental Clinic", "out_of_service", "medium", "2026-03-11", "2026-09-11"),
    ("CHL-601", "hosp_a", "HVAC Chiller 2", "hvac", "Roof Plant", "in_service", "medium", "2026-05-05", "2026-11-05"),
    ("MRI-701", "hosp_b", "MagnaScan 3T MRI", "imaging", "Radiology Suite 1", "in_service", "critical", "2026-08-30", "2026-11-30"),
    ("VEN-151", "hosp_b", "AeroVent X2 Ventilator", "ventilator", "NICU Bay 1", "in_service", "high", "2026-05-18", "2026-11-18"),
    ("INF-251", "hosp_b", "FlowSure 300 Infusion Pump", "infusion_pump", "Oncology Day Unit", "advisory", "high", "2026-06-01", "2026-12-01"),
    ("STE-551", "hosp_b", "SteamPro 600 Sterilizer", "sterilizer", "CSSD Line 2", "in_service", "high", "2026-09-22", "2026-12-22"),
    ("GEN-451", "hosp_b", "Emergency Generator 800 kVA", "generator", "Energy Centre", "in_service", "critical", "2026-10-03", "2026-11-03"),
]

# wo_id, tenant_id, asset_id, opened, priority, status, summary
WORK_ORDERS = [
    ("WO-1001", "hosp_a", "VEN-101", "2026-10-11", "high", "open", "6-month PM overdue; tag out if not done by 2026-10-24"),
    ("WO-1002", "hosp_a", "INF-201", "2026-07-20", "medium", "in_progress", "Firmware update to 4.2 per ALERT-A-INF-2026-07"),
    ("WO-1003", "hosp_a", "AUT-501", "2026-09-12", "medium", "open", "Door seal leak; awaiting part"),
    ("WO-1004", "hosp_a", "GEN-401", "2026-10-01", "low", "closed", "Monthly load test passed, transfer 7 s"),
    ("WO-2001", "hosp_b", "MRI-701", "2026-10-15", "high", "open", "Helium at 61 percent; schedule refill"),
    ("WO-2002", "hosp_b", "INF-251", "2026-07-25", "medium", "open", "Firmware update to 4.2 pending"),
]

# Commercially sensitive (synthetic) data that an operations chatbot should never need.
# contract_id, tenant_id, vendor, scope, annual_value_sar, renewal_date, account_manager_email
VENDOR_CONTRACTS = [
    ("CT-A-01", "hosp_a", "AeroMed Services (fictional)", "Ventilator full-service", 1_240_000, "2027-03-31", "am@aeromed.example"),
    ("CT-A-02", "hosp_a", "PowerSafe Gulf (fictional)", "Generator maintenance", 385_000, "2026-12-31", "sales@powersafe.example"),
    ("CT-B-01", "hosp_b", "MagnaScan Arabia (fictional)", "MRI uptime contract", 2_900_000, "2027-06-30", "kam@magnascan.example"),
]
