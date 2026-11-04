import sys
sys.path.insert(0, ".")
import asyncio
import base64
import os
import json
from app.services.health_exchange import HealthInfoCryptoService, FHIRBundleGenerator, TransactionTracker
from app.abdm.consent_repository import consent_repository

async def test():
    try:
        consent_id = "f47c3359-c3af-42a7-8a8a-56e63bc90739"
        consent_artifact = await consent_repository.find_by_consent_id(consent_id)
        print("consent_artifact:", consent_artifact)

        priv_b64, pub_b64 = HealthInfoCryptoService.generate_key_pair()
        print("keys generated:", len(priv_b64), len(pub_b64))

        # Test encrypting
        peer_pub_b64 = "BCpsBW37KgfLyjxJK0zHHG26hDjxzK368DEO4PapzFhQM0cghZziKuvJh5/anTnHitVHKMn0Owr1HvcH1fm0DpA="
        # Note: peer_pub_bytes length
        raw_b64 = base64.b64decode(peer_pub_b64.encode('utf-8'))
        print("peer_pub_bytes length:", len(raw_b64))

        bundle = FHIRBundleGenerator.generate_bundle("Prescription", "sroshan110707@sbx", "CC001")
        print("bundle generated:", type(bundle))
    except Exception as e:
        import traceback
        traceback.print_exc()

asyncio.run(test())
