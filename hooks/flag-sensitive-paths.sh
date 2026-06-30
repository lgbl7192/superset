#!/bin/sh
payload=$(cat)
file=$(echo "$payload" | jq -r .file_path)
if echo "$file" | grep -qE "superset/security/|superset/views/sql_lab/|flask_appbuilder"; then
  jq -n '{continue:false, permission:"deny",
    userMessage:"This path requires human review — auto-remediation blocked by hooks/flag-sensitive-paths.sh"}'
else
  jq -n '{continue:true, permission:"allow"}'
fi
