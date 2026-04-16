# Backup System – Test Checklist

## .env additions (backend/.env)

```
# Optional: AES-encrypt backup zips. If set, backups are password-protected.
BACKUP_ENCRYPTION_KEY=your-secret-password
```

---

## 1. Manual backup creates zip + summary files
- [ ] Log in to admin panel (nalcsbaru@gmail.com / admin123, 2FA)
- [ ] Go to Settings → Backup Settings
- [ ] Click "Manual Backup Now"
- [ ] Button shows "Running…" then "Backup completed" toast
- [ ] Last backup time updates
- [ ] Backup history shows new entry with size
- [ ] Check `backend/backups/` – zip exists (e.g. `backup-YYYYMMDD-HHMMSS.zip`)
- [ ] Check `backend/backups/` – summary files exist: `backup-YYYYMMDD-HHMMSS-summary.json` and `backup-YYYYMMDD-HHMMSS-summary.txt`

## 2. Summary shows correct counts
- [ ] Open backup-summary.json – verify `tables` has row counts per table
- [ ] Verify `key_tables_highlight` has scans, reports, audit_logs, admin_users, user_security, system_settings
- [ ] Backup Health card shows key table counts

## 3. Checksum stored and verified
- [ ] backup-summary.json has `checksum_sha256` field
- [ ] Backup Health card shows short checksum (first 16 chars + ...)
- [ ] Restore verifies checksum before applying

## 4. Restore refuses tampered zip
- [ ] Create a backup, note its path
- [ ] Manually edit the zip file (e.g. append a byte) or corrupt it
- [ ] Try Restore from that backup
- [ ] Should get error: "Backup file checksum mismatch – file may be corrupted"

## 5. Toggle auto backup schedules job
- [ ] Go to Settings → Backup Settings
- [ ] Toggle "Automatic Backup" ON
- [ ] Change "Backup Time of Day" (e.g. 04:00)
- [ ] Change "Retention" (e.g. 30 days)
- [ ] Verify "Next Scheduled Backup" shows expected time
- [ ] Log in backend console – should see "Backup scheduler: daily at HH:MM"

## 6. Download works
- [ ] After at least one manual backup, click "Download latest backup"
- [ ] Browser downloads a zip file
- [ ] Verify zip contains `dump.sql`

## 7. Restore works (dev safe)
- [ ] Open "Restore from backup" modal
- [ ] Select a backup from the list
- [ ] Choose mode: SAFE (settings only) or FULL
- [ ] Type "RESTORE" and click Restore
- [ ] Toast shows success (and "restart backend recommended" for zip backups)
- [ ] For zip restore: backend restarts recommended; database is replaced

## 8. Backup Health card + View/Download summary
- [ ] Last backup time displays correctly
- [ ] Next scheduled backup shows when auto enabled
- [ ] Recent history shows backup size and status
- [ ] "View summary" opens modal with JSON
- [ ] "Download summary" downloads backup-summary.json
