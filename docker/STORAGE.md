# Content storage

This standalone Compose file runs the API, web frontend, PostgreSQL and Redis.
It does not install an object-storage server or a bucket-creation administrator.

Filesystem content persists in lh_content mounted at /app/content. The existing
LEARNHOUSE_CONTENT_DELIVERY_TYPE setting is preserved; the Compose file does not
override it. For s3api, provision the private endpoint and bucket separately and
provide scoped service credentials through the deployment secret mechanism.

For Wafercad suite deployments, use the orchestrator manifest and storage runbook.
Do not start a second standalone content stack alongside it. Existing populated
object storage requires a verified migration before changing the delivery type.
Removing a service definition does not migrate or delete its external data.
