def set_payload_by_filter(client, collection_name, filter_condition, payload):
    """
    Update payloads in bulk based on a filter condition.

    Args:
        client: The Qdrant client instance.
        collection_name: The name of the collection to update.
        filter_condition: The condition to filter the documents.
        payload: The new payload to set for the filtered documents.
    """
    # Use scroll to fetch all matching documents
    points = client.scroll(collection_name, filter=filter_condition)

    # Update the payload for the fetched documents
    client.set_payload(points=points, payload=payload)
