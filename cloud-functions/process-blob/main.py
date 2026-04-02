# ABOUTME: Cloud Function triggered by GCS object finalize events
# ABOUTME: Performs content moderation and video thumbnail extraction

import os
import json
import requests
from datetime import datetime
from google.cloud import storage
from google.cloud import vision
from google.cloud.vision_v1 import types

# Fastly KV API endpoint for metadata updates
# This would be a webhook endpoint on your Fastly service
METADATA_WEBHOOK_URL = os.environ.get('METADATA_WEBHOOK_URL', '')
METADATA_WEBHOOK_SECRET = os.environ.get('METADATA_WEBHOOK_SECRET', '')


def process_blob(event, context):
    """
    Triggered by a new object in GCS bucket.

    Args:
        event: GCS event data
        context: Cloud Function context
    """
    bucket_name = event['bucket']
    blob_name = event['name']
    content_type = event.get('contentType', 'application/octet-stream')

    print(f"Processing: gs://{bucket_name}/{blob_name} ({content_type})")

    # Skip thumbnails (they're our output, not input)
    if blob_name.startswith('thumbnails/'):
        print("Skipping thumbnail")
        return

    # Process based on content type
    if content_type.startswith('image/'):
        result = check_image_safety(bucket_name, blob_name)
        handle_moderation_result(bucket_name, blob_name, result)

    elif content_type.startswith('video/'):
        # For videos: extract thumbnail, then check thumbnail
        thumbnail_path = extract_video_thumbnail(bucket_name, blob_name)
        if thumbnail_path:
            result = check_image_safety(bucket_name, thumbnail_path)
            handle_moderation_result(bucket_name, blob_name, result, thumbnail_path)
        else:
            # Thumbnail extraction failed, mark as pending review
            update_metadata(blob_name, 'pending', None, None)
    else:
        # Non-image/video content, auto-approve
        update_metadata(blob_name, 'active', None, create_moderation_result(True))


def check_image_safety(bucket_name: str, blob_name: str) -> dict:
    """
    Check image safety using Vision API SafeSearch.

    Returns:
        dict with is_flagged, reason, scores
    """
    client = vision.ImageAnnotatorClient()

    image = types.Image(
        source=types.ImageSource(
            gcs_image_uri=f'gs://{bucket_name}/{blob_name}'
        )
    )

    response = client.safe_search_detection(image=image)
    safe = response.safe_search_annotation

    # Get likelihood values
    likelihood_name = vision.Likelihood

    # Flag if LIKELY or VERY_LIKELY for adult or violence
    is_flagged = (
        safe.adult >= likelihood_name.LIKELY or
        safe.violence >= likelihood_name.LIKELY
    )

    scores = {
        'adult': likelihood_name(safe.adult).name,
        'violence': likelihood_name(safe.violence).name,
        'racy': likelihood_name(safe.racy).name,
    }

    reason = None
    if is_flagged:
        reasons = []
        if safe.adult >= likelihood_name.LIKELY:
            reasons.append(f"adult:{scores['adult']}")
        if safe.violence >= likelihood_name.LIKELY:
            reasons.append(f"violence:{scores['violence']}")
        reason = ", ".join(reasons)

    return {
        'is_flagged': is_flagged,
        'reason': reason,
        'scores': scores
    }


def extract_video_thumbnail(bucket_name: str, blob_name: str) -> str:
    """
    Extract a thumbnail frame from video.
    For now, uses first frame via simple ffmpeg or Cloud Video Intelligence.

    Returns:
        Path to uploaded thumbnail, or None if failed
    """
    # Simple approach: download video, extract frame with ffprobe/ffmpeg
    # For production, consider Cloud Video Intelligence API

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)

    # For MVP: just copy first frame as thumbnail
    # This is a placeholder - real implementation would use ffmpeg or Video Intelligence
    thumbnail_path = f'thumbnails/{blob_name}'

    # TODO: Implement actual thumbnail extraction
    # Option 1: Cloud Run with ffmpeg
    # Option 2: Video Intelligence API shot detection

    print(f"TODO: Extract thumbnail to {thumbnail_path}")
    return None  # Return None until implemented


def handle_moderation_result(bucket_name: str, blob_name: str, result: dict, thumbnail_path: str = None):
    """Handle the moderation result by updating moderation metadata only."""
    if result['is_flagged']:
        print(f"Content flagged: {result['reason']}")

        # Update metadata to restricted/deleted
        update_metadata(blob_name, 'restricted', thumbnail_path,
                       create_moderation_result(False, result['scores']))
    else:
        # Content is safe
        update_metadata(blob_name, 'active', thumbnail_path,
                       create_moderation_result(True, result['scores']))


def create_moderation_result(is_safe: bool, scores: dict = None) -> dict:
    """Create a moderation result object."""
    result = {
        'checked_at': datetime.utcnow().isoformat() + 'Z',
        'is_safe': is_safe
    }
    if scores:
        result['scores'] = scores
    return result


def update_metadata(blob_name: str, status: str, thumbnail: str, moderation: dict):
    """
    Update blob metadata in Fastly KV store via webhook.

    In production, this calls a secure webhook endpoint on your Fastly service
    that updates the KV store metadata.
    """
    if not METADATA_WEBHOOK_URL:
        print(f"METADATA_WEBHOOK_URL not set, skipping update for {blob_name}")
        print(f"  status={status}, thumbnail={thumbnail}, moderation={moderation}")
        return

    payload = {
        'sha256': blob_name,
        'status': status,
        'thumbnail': thumbnail,
        'moderation': moderation
    }

    headers = {
        'Content-Type': 'application/json',
        'X-Webhook-Secret': METADATA_WEBHOOK_SECRET
    }

    try:
        response = requests.post(METADATA_WEBHOOK_URL, json=payload, headers=headers)
        response.raise_for_status()
        print(f"Updated metadata for {blob_name}")
    except Exception as e:
        print(f"Failed to update metadata: {e}")
