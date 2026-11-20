# Publish UPIShield on Render

This setup serves the React app and FastAPI/OCR API from one Render web service. The browser uses the same public HTTPS origin for both.

## 1. GitHub source

The project is in [Debraj141/UPIShiled_react](https://github.com/Debraj141/UPIShiled_react). To publish later changes, run these commands from the project folder:

```powershell
git add .
git commit -m "Describe your change"
git push
```

Do not commit real payment screenshots or secret values.

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

## Build the Android app

The Android project uses Capacitor and sends scans to the public Render API. Each push to `main` runs the **Build Android APK** GitHub Actions workflow.

1. Open the repository's **Actions** tab and select the latest successful **Build Android APK** run.
2. Download the `upishield-debug-apk` artifact and extract `app-debug.apk`.
3. Transfer the APK to an Android phone and install it. Android may ask you to allow installation from that file source.

The debug APK is for direct testing, not Google Play publishing. This project requires Android Studio and an Android SDK to build locally; GitHub Actions builds it without installing those tools on the development laptop.
