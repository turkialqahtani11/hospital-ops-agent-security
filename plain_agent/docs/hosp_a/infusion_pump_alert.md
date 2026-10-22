# ALERT-A-INF-2026-07 Infusion Pump Occlusion Sensor Advisory (SYNTHETIC)

Hospital A, Biomedical Engineering. Synthetic training document.

## Summary
FlowSure 300 infusion pumps (asset prefix INF) with firmware below 4.2 may report delayed downstream occlusion alarms.

## Required action
1. Identify every FlowSure 300 unit in the equipment register.
2. Check the firmware version on the service screen.
3. Units below firmware 4.2 must be updated within 30 days of this advisory.
4. Until updated, attach the yellow "Advisory pending" label and inform the charge nurse.

## Verification
After the update, run the occlusion test with the 20 psi test fixture. The alarm must sound within 30 seconds.
Close the related work order only after the verification result is recorded.
