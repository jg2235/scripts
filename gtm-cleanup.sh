#!/bin/bash
# Shell script to parse F5 BIG-IP GTM (DNS) configuration and list objects with zero hit counts
# Covers Wide IPs, Pool Members, Servers, and iRules
# Also identifies unreferenced pools (not attached to wide IPs or mentioned in iRules)
# Outputs in markdown table format
# Provides tmsh cleanup commands but does not execute them
 
# Function to collect zero-hit wide IPs
collect_zero_wideips() {
  wideip_lines=$(tmsh list gtm wideip | grep '^gtm wideip')
  while read -r line; do
    type=$(echo "$line" | awk '{print $3}')
    name=$(echo "$line" | awk '{print $4}')
    stats=$(tmsh show gtm wideip $type $name | grep -A 3 'Requests')
    total=$(echo "$stats" | grep 'Total' | awk '{print $2}' | head -1)
    if [ "$total" = "0" ]; then
      echo "$type $name"
    fi
  done <<< "$wideip_lines"
}
 
# Function to collect zero-hit pool members
collect_zero_pms() {
  pool_lines=$(tmsh list gtm pool | grep '^gtm pool')
  while read -r line; do
    type=$(echo "$line" | awk '{print $3}')
    pool=$(echo "$line" | awk '{print $4}')
    members=$(tmsh show gtm pool $type $pool | grep 'Gtm::Pool Member:' | awk '{print $3}')
    for member in $members; do
      stats=$(tmsh show gtm pool $type $pool members { $member } | grep -A 3 'Requests')
      total=$(echo "$stats" | grep 'Total' | awk '{print $2}' | head -1)
      if [ "$total" = "0" ]; then
        echo "$type $pool $member"
      fi
    done
  done <<< "$pool_lines"
}
 
# Function to collect zero-hit servers
collect_zero_servers() {
  server_list=$(tmsh list gtm server | grep '^gtm server' | awk '{print $3}')
  for server in $server_list; do
    stats=$(tmsh show gtm server $server | grep -A 3 'Requests')
    total=$(echo "$stats" | grep 'Total' | awk '{print $2}' | head -1)
    if [ "$total" = "0" ]; then
      echo "$server"
    fi
  done
}
 
# Function to collect zero-hit iRules (for GTM/DNS iRules under gtm rule)
collect_zero_irules() {
  irule_list=$(tmsh list gtm rule | grep '^gtm rule' | awk '{print $3}')
  for irule in $irule_list; do
    stats=$(tmsh show gtm rule $irule)
    total=$(echo "$stats" | grep -A 3 'Executions' | grep 'Total' | awk '{print $2}' | head -1)
    if [ "$total" = "0" ]; then
      echo "$irule"
    fi
  done
}
 
# Function to collect unreferenced pools
collect_unreferenced_pools() {
  pool_lines=$(tmsh list gtm pool | grep '^gtm pool')
 
  # Build pool_map for name to type
  declare -A pool_map
  while read -r line; do
    type=$(echo "$line" | awk '{print $3}')
    name=$(echo "$line" | awk '{print $4}')
    pool_map["$name"]=$type
  done <<< "$pool_lines"
 
  declare -A referenced
  # Check wide IPs for attached pools
  wideip_lines=$(tmsh list gtm wideip | grep '^gtm wideip')
  while read -r line; do
    type=$(echo "$line" | awk '{print $3}')
    name=$(echo "$line" | awk '{print $4}')
    content=$(tmsh list gtm wideip $type $name)
    # Improved extraction for pool names
    pools_in_wideip=$(echo "$content" | sed -n '/pools {/,/}/p' | sed 's/^\s*//' | grep '{' | awk '{print $1}' | sort -u)
    for p in $pools_in_wideip; do
      pool_type=${pool_map["$p"]}
      if [ -n "$pool_type" ]; then
        referenced["$pool_type $p"]=1
      fi
    done
  done <<< "$wideip_lines"
  # Check iRules for pool references
  irule_list=$(tmsh list gtm rule | grep '^gtm rule' | awk '{print $3}')
  for irule in $irule_list; do
    content=$(tmsh list gtm rule $irule)
    pools_in_irule=$(echo "$content" | grep 'GTM::pool ' | awk '{print $2}' | tr -d '"' | sort -u)
    for p in $pools_in_irule; do
      pool_type=${pool_map["$p"]}
      if [ -n "$pool_type" ]; then
        referenced["$pool_type $p"]=1
      fi
    done
  done
  while read -r line; do
    type=$(echo "$line" | awk '{print $3}')
    name=$(echo "$line" | awk '{print $4}')
    pool="$type $name"
    if [ -z "${referenced[$pool]}" ]; then
      echo "$pool"
    fi
  done <<< "$pool_lines"
}
 
# Collect data
mapfile -t zero_wideips < <(collect_zero_wideips)
mapfile -t zero_pms < <(collect_zero_pms)
mapfile -t zero_servers < <(collect_zero_servers)
mapfile -t zero_irules < <(collect_zero_irules)
mapfile -t unreferenced_pools < <(collect_unreferenced_pools)
 
# Output table
echo "Objects with zero hit counts or unreferenced:"
echo ""
echo "| Object Type | Name |"
echo "|----------------|-------------------------------|"
for wi in "${zero_wideips[@]}"; do
  type=$(echo "$wi" | awk '{print $1}')
  name=$(echo "$wi" | awk '{print $2}')
  echo "| Wide IP | $type $name |"
done
for pm in "${zero_pms[@]}"; do
  type=$(echo "$pm" | awk '{print $1}')
  pool=$(echo "$pm" | awk '{print $2}')
  member=$(echo "$pm" | awk '{print $3}')
  echo "| Pool Member | $type $pool/$member |"
done
for server in "${zero_servers[@]}"; do
  echo "| Server | $server |"
done
for irule in "${zero_irules[@]}"; do
  echo "| iRule | $irule |"
done
for pool in "${unreferenced_pools[@]}"; do
  echo "| Unreferenced Pool | $pool |"
done
 
# Output cleanup commands
echo ""
echo "Cleanup commands (do not execute without verification; deletions may fail if objects are referenced):"
for wi in "${zero_wideips[@]}"; do
  type=$(echo "$wi" | awk '{print $1}')
  name=$(echo "$wi" | awk '{print $2}')
  echo "tmsh delete gtm wideip $type $name"
done
for pm in "${zero_pms[@]}"; do
  type=$(echo "$pm" | awk '{print $1}')
  pool=$(echo "$pm" | awk '{print $2}')
  member=$(echo "$pm" | awk '{print $3}')
  echo "tmsh modify gtm pool $type $pool members delete { $member }"
done
for server in "${zero_servers[@]}"; do
  echo "tmsh delete gtm server $server"
done
for irule in "${zero_irules[@]}"; do
  echo "tmsh delete gtm rule $irule"
done
for pool in "${unreferenced_pools[@]}"; do
  type=$(echo "$pool" | awk '{print $1}')
  name=$(echo "$pool" | awk '{print $2}')
  echo "tmsh delete gtm pool $type $name"
done
