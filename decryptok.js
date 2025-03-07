"use strict";

(() => {
  var __defProp = Object.defineProperty;
  var __name = (target, value) =>
    __defProp(target, "name", { value, configurable: true });

  // src/worker.js
  (() => {
    var __defProp2 = Object.defineProperty;
    var __name2 = /* @__PURE__ */ __name(
      (target, value) =>
        __defProp2(target, "name", { value, configurable: true }),
      "__name"
    );

    addEventListener("fetch", (event) => {
      event.respondWith(handleRequest(event.request));
    });

    async function handleRequest(request) {
      const url = new URL(request.url);
      const path = url.pathname;
      console.log("Received request:", request.method, path);

      // Dynamically handle CORS
      const origin = request.headers.get("Origin");
      const corsHeaders = {
        "Access-Control-Allow-Origin": origin || "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "86400", // Cache preflight for 1 day
      };

      if (request.method === "OPTIONS") {
        return new Response(null, {
          headers: corsHeaders,
        });
      }

      if (path === "/api/consent" && request.method === "POST") {
        return await handleConsentRequest(request, corsHeaders);
      }

      if (path === "/cmp-script.js") {
        return new Response(CMP_SCRIPT, {
          headers: {
            "Content-Type": "application/javascript",
            ...corsHeaders,
          },
        });
      }

      return new Response("CMP worker is running", {
        status: 200,
        headers: corsHeaders,
      });
    }

    __name(handleRequest, "handleRequest");
    __name2(handleRequest, "handleRequest");

    // Encryption and decryption helper functions
    async function importKey(rawKey) {
      return await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
    }

    async function encryptData(data, key, iv) {
      const encoder = new TextEncoder();
      const encodedData = encoder.encode(data);
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedData
      );
      return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    }

    async function decryptData(encrypted, key, iv) {
      const encryptedBuffer = Uint8Array.from(atob(encrypted), (c) =>
        c.charCodeAt(0)
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encryptedBuffer
      );
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    }

    async function handleConsentRequest(request, corsHeaders) {
      const headers = request.headers;
      const ipAddress = headers.get("CF-Connecting-IP");

      if (request.method === "POST") {
        try {
          const data = await request.json();
          const { userId, preferences, policyVersion } = data;
          const iv = new Uint8Array(preferences.iv);
          const rawKey = new Uint8Array(preferences.key);
          const timestamp = new Date().toISOString();

          // Import the encryption key
          const key = await importKey(rawKey.buffer);

          // Decrypt the preferences
          const decryptedPreferences = await decryptData(preferences.encryptedData, key, iv);

          // Save data to KV without encryption
          const consentData = {
            user_id: userId, // Not encrypted, human-readable
            ip_address: ipAddress || "Unknown", // Not encrypted, human-readable
            consent_preferences: JSON.parse(decryptedPreferences), // Unencrypted, human-readable
            timestamp,
            policy_version: policyVersion || "1.0",
          };

          console.log("Consent data to save:", consentData);

          // Save consent data to KV
          await CMP_STORAGE.put(userId, JSON.stringify(consentData));

          // Prepare response
          const response = new Response("Preferences saved", {
            status: 200,
            headers: corsHeaders,
          });

          response.headers.set(
            "Set-Cookie",
            `consent-given=true; path=/; max-age=31536000; Secure; SameSite=Strict`
          );
          response.headers.set(
            "Set-Cookie",
            `consent-preferences=${encodeURIComponent(
              JSON.stringify(consentData.consent_preferences)
            )}; path=/; max-age=31536000; Secure; SameSite=Strict`
          );
          response.headers.set(
            "Set-Cookie",
            `consent-timestamp=${new Date().toISOString()}; path=/; max-age=31536000; Secure; SameSite=Strict`
          );
          response.headers.set(
            "Set-Cookie",
            `consent-policy-version=1.2; path=/; max-age=31536000; Secure; SameSite=Strict`
          );

          return response;
        } catch (error) {
          console.error("Error processing consent:", error);
          return new Response("Error processing consent", {
            status: 500,
            headers: corsHeaders,
          });
        }
      }

      if (request.method === "GET") {
        const userId = new URL(request.url).searchParams.get("userId");

        // Fetch consent data from KV
        const consentData = await CMP_STORAGE.get(userId);

        if (!consentData) {
          return new Response("No preferences found", {
            status: 404,
            headers: corsHeaders,
          });
        }

        console.log("Data from KV:", consentData);

        // Return consent data
        return new Response(consentData, {
          status: 200,
          headers: corsHeaders,
        });
      }

      return new Response("Invalid method", {
        status: 405,
        headers: corsHeaders,
      });
    }

    __name(handleConsentRequest, "handleConsentRequest");
    __name2(handleConsentRequest, "handleConsentRequest");

    const CMP_SCRIPT = `(async function () {
      let consentState = {};
      let observer;
    
      async function hashData(data) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
        return Array.from(new Uint8Array(hashBuffer))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      }
    
      async function generateKey() {
        const key = await crypto.subtle.generateKey(
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"]
        );
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const exportedKey = await crypto.subtle.exportKey("raw", key);
        return { secretKey: exportedKey, iv };
      }
    
      async function encryptData(data, key, iv) {
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(data);
        const importedKey = await crypto.subtle.importKey(
          "raw",
          key,
          { name: "AES-GCM" },
          false,
          ["encrypt"]
        );
        const encrypted = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: iv },
          importedKey,
          encodedData
        );
        return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
      }
    
      function loadConsentState() {
        const consentGiven = localStorage.getItem("consent-given");
        if (consentGiven === "true") {
          consentState = JSON.parse(localStorage.getItem("consent-preferences")) || {};
          consentState.timestamp = localStorage.getItem("consent-timestamp");
          consentState.policy_version = localStorage.getItem("consent-policy-version");
        }
      }
    
      async function saveConsentState(preferences) {
        const userId = await hashData(localStorage.getItem("user-id") || "anonymous-user");
        const encryptionKey = await generateKey();
    
        const encryptedPreferences = await encryptData(
          JSON.stringify(preferences),
          encryptionKey.secretKey,
          encryptionKey.iv
        );
        localStorage.setItem("consent-given", "true");
        localStorage.setItem("consent-preferences", JSON.stringify(encryptedPreferences));
        localStorage.setItem("consent-timestamp", new Date().toISOString());
        localStorage.setItem("consent-policy-version", "1.2");
    
        fetch("https://cmp-webflow-worker.web-8fb.workers.dev/api/consent", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            userId,
            preferences: {
              encryptedData: encryptedPreferences,
              iv: Array.from(encryptionKey.iv),
              key: Array.from(new Uint8Array(encryptionKey.secretKey))
            },
            policyVersion: "1.2"
          }),
        })
          .then((response) => response.text())
          .then((data) => console.log("Response from server:", data))
          .catch((error) => console.error("Error sending consent data:", error));
      }
    
      function blockAnalyticsRequests() {
        const blockedUrls = ["google-analytics.com", "matomo.org", "facebook.com/tr"];
        self.addEventListener("fetch", (event) => {
          const requestUrl = event.request.url;
          if (
            blockedUrls.some((url) => requestUrl.includes(url)) &&
            (!consentState.analytics || consentState.analytics === "false")
          ) {
            event.respondWith(new Response(null, { status: 204 }));
            console.log("Blocked analytics request:", requestUrl);
          }
        });
      }
    
      function blockDynamicScripts() {
        observer = new MutationObserver((mutations) => {
          mutations.forEach((mutation) => {
            if (mutation.type === "childList") {
              mutation.addedNodes.forEach((node) => {
                if (node.tagName === "SCRIPT" && node.src) {
                  if (
                    !consentState.analytics &&
                    /google-analytics|matomo|facebook/.test(node.src)
                  ) {
                    node.remove();
                    console.log("Blocked dynamic script:", node.src);
                  }
                }
              });
            }
          });
        });
        observer.observe(document.body, { childList: true, subtree: true });
      }
    
      function updateConsentState(preferences) {
        consentState = preferences;
    
        localStorage.setItem("consent-preferences", JSON.stringify(preferences));
        localStorage.setItem("consent-timestamp", new Date().toISOString());
        localStorage.setItem("consent-policy-version", "1.2");
    
        saveConsentState(preferences);
      }
    
      document.addEventListener("DOMContentLoaded", function () {
        loadConsentState();
        blockAnalyticsRequests();
        blockDynamicScripts();
    
        const acceptButton = document.querySelector(".accept-btn");
        const toggleConsentButton = document.getElementById("toggle-consent-btn");
        const consentBanner = document.getElementById("consent-banner");
    
        if (acceptButton) {
          acceptButton.addEventListener("click", function () {
            updateConsentState({
              necessary: document.getElementById("necessary-checkbox")?.checked,
              preferences: document.getElementById("preferences-checkbox")?.checked,
              analytics: document.getElementById("analytics-checkbox")?.checked,
              marketing: document.getElementById("marketing-checkbox")?.checked,
            });
    
            if (consentBanner) {
              consentBanner.style.display = "none";
            }
          });
        }
    
        if (toggleConsentButton) {
          toggleConsentButton.addEventListener("click", function () {
            if (consentBanner) {
              consentBanner.style.display = "block";
            }
          });
        }
      });
    
      window.updateConsentState = updateConsentState;
    })();
    `;
  })();
})();
