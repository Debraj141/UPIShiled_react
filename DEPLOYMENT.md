# Publish UPIShield on Render

This setup serves the React app and FastAPI/OCR API from one Render web service. The browser uses the same public HTTPS origin for both.

## 1. Push the project to GitHub

Create a GitHub repository. It can be private; the deployed app will still be publicly accessible. From PowerShell in this project folder, run:

```powershell
git init
git add .
git commit -m "Prepare UPIShield for Render"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

Replace the remote URL with the repository you created. Do not commit real payment screenshots or secret values.

## 2. Create the Render service

1. Sign in to Render and choose **New → Blueprint**.
2. Connect the GitHub repository.
3. Review the `upishield` service from `render.yaml` and deploy it.
4. Wait for the deploy and health check to finish. Render will show a public `https://...onrender.com` address.

## Notes

- The free Render service may sleep when idle, so the first request after a quiet period can take longer than three seconds.
- History and duplicate-ID tracking are in memory and reset when the service restarts or redeploys. This is a demo deployment, not durable transaction storage.
- The service accepts uploaded images for analysis and has no user login. Avoid uploading real or sensitive payment screenshots until authentication, abuse protection, and a retention policy are added.
- A screenshot verdict is not proof of settlement. Verify receipt in the official bank or UPI app.
