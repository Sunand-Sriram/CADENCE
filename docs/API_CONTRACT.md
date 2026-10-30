# API CONTRACT v1

Base URL: http://<host>:8900  (FastAPI, served by crs_core/api.py on Kali)

GET  /api/health -> {"status":"ok","llm_mode":"mock|live"}
POST /api/ingest  body {"repo_url":"<github url>"} -> {"job_id":str,"repo":str,"commit":str,"status":"started"}  (clones the repo, crypto-filters, runs CBOM+risk+quantum)
GET  /api/ingest/{job_id} -> {"job_id":str,"status":"running|done|error","repo":str,"commit":str,"error":str|null}
GET  /api/cbom?job_id=.. -> {"assets":[{"asset_id","algorithm","operation","file_path","line","is_weak","weak_reason"}]}
GET  /api/risk?job_id=.. -> {"assessments":[{"asset_id","algorithm","score","band","factors","rationale"}]}
GET  /api/quantum?job_id=.. -> {"assessments":[{"asset_id","algorithm","shor_broken","grover_weakened","mosca_x","mosca_y","mosca_z","mosca_at_risk","urgency","recommended_pqc","note"}]}
GET  /api/compare?asset_id=..&job_id=.. -> {"asset_id","algorithm","candidates":[{"target_algorithm","validates","builds","crash_fixed","regression_pass","risk_before","risk_after","risk_drop","patch_hash"}],"recommended":str|null}
POST /api/approve body {"asset_id":str,"job_id":str,"chosen_algorithm":str} -> {"status":"approved|refused","asset_id","chosen_algorithm","risk_before":int,"risk_after":int,"patch_hash":str,"note":str}
GET  /api/evidence/{asset_id}?job_id=.. -> the full evidence bundle JSON for that asset

## Rules

1. All responses are JSON.
2. CORS must be enabled so the frontend can call from a browser.
3. `job_id` defaults to `default` for the pre-loaded `targets/target` if ingest hasn't been run, so the frontend works even before a real clone.
4. Endpoints that aren't ready yet must return a stub with the correct shape (empty arrays / placeholder values) so the frontend can be built against them immediately.
5. Field names are frozen — changing one requires editing this file and noting it in `COMMS.md`.
