
#!/bin/bash
# Shell script to parse F5 BIG-IP configuration and list objects with zero hit counts
# Covers Virtual Servers, Pool Members, Nodes, and iRules
# Also identifies unreferenced pools (not attached to virtual servers or mentioned in iRules)
# Outputs in markdown table format
# Provides tmsh cleanup commands but does not execute them

# Function to collect zero-hit virtual servers
collect_zero_vs() {
  vs_list=$(tmsh list ltm virtual | grep '^ltm virtual' | awk '{print $3}')
  declare -a zero_vs
  for vs in $vs_list; do
    stats=$(tmsh show ltm virtual $vs | grep "Total Connections")
    total=$(echo "$stats" | awk '{print $3}')
    if [ "$total" = "0" ]; then
      zero_vs+=("$vs")
    fi
  done
  echo "${zero_vs[@]}"
}

# Function to collect zero-hit pool members
collect_zero_pms() {
  pool_list=$(tmsh list ltm pool | grep '^ltm pool' | awk '{print $3}')
  declare -a zero_pms
  for pool in $pool_list; do
    members=$(tmsh show ltm pool $pool | grep 'Ltm::Pool Member:' | awk '{print $3}')
    for member in $members; do
      stats=$(tmsh show ltm pool $pool members { $member } | grep "Total Connections")
      total=$(echo "$stats" | awk '{print $3}')
      if [ "$total" = "0" ]; then
        zero_pms+=("$pool $member")
      fi
    done
  done
  echo "${zero_pms[@]}"
}

# Function to collect zero-hit nodes
collect_zero_nodes() {
  node_list=$(tmsh list ltm node | grep '^ltm node' | awk '{print $3}')
  declare -a zero_nodes
  for node in $node_list; do
    stats=$(tmsh show ltm node $node | grep "Total Connections")
    total=$(echo "$stats" | awk '{print $3}')
    if [ "$total" = "0" ]; then
      zero_nodes+=("$node")
    fi
  done
  echo "${zero_nodes[@]}"
}

# Function to collect zero-hit iRules
collect_zero_irules() {
  irule_list=$(tmsh list ltm rule | grep '^ltm rule' | awk '{print $3}')
  declare -a zero_irules
  for irule in $irule_list; do
    stats=$(tmsh show ltm rule $irule)
    total=$(echo "$stats" | grep -A 3 'Executions' | grep 'Total' | awk '{print $2}' | head -1)
    if [ "$total" = "0" ]; then
      zero_irules+=("$irule")
    fi
  done
  echo "${zero_irules[@]}"
}

# Function to collect unreferenced pools
collect_unreferenced_pools() {
  pool_list=$(tmsh list ltm pool | grep '^ltm pool' | awk '{print $3}')
  declare -A referenced
  # Check virtual servers for attached pools
  vs_list=$(tmsh list ltm virtual | grep '^ltm virtual' | awk '{print $3}')
  for vs in $vs_list; do
    pool=$(tmsh list ltm virtual $vs | grep 'pool ' | awk '{print $2}')
    if [ ! -z "$pool" ]; then
      referenced["$pool"]=1
    fi
  done
  # Check iRules for pool references
  irule_list=$(tmsh list ltm rule | grep '^ltm rule' | awk '{print $3}')
  for irule in $irule_list; do
    content=$(tmsh list ltm rule $irule)
    pools_in_irule=$(echo "$content" | grep 'pool ' | awk '{print $2}' | sort -u)
    for p in $pools_in_irule; do
      # If pool name lacks partition, assume /Common/
      if [[ ! "$p" =~ ^/ ]]; then
        p="/Common/$p"
      fi
      referenced["$p"]=1
    done
  done
  declare -a unreferenced_pools
  for pool in $pool_list; do
    if [ -z "${referenced[$pool]}" ]; then
      unreferenced_pools+=("$pool")
    fi
  done
  echo "${unreferenced_pools[@]}"
}

# Collect data
zero_vs=($(collect_zero_vs))
zero_pms=($(collect_zero_pms))
zero_nodes=($(collect_zero_nodes))
zero_irules=($(collect_zero_irules))
unreferenced_pools=($(collect_unreferenced_pools))

# Output table
echo "Objects with zero hit counts or unreferenced:"
echo ""
echo "| Object Type | Name |"
echo "|----------------|-------------------------------|"
for vs in "${zero_vs[@]}"; do
  echo "| Virtual Server | $vs |"
done
for pm in "${zero_pms[@]}"; do
  pool=$(echo $pm | awk '{print $1}')
  member=$(echo $pm | awk '{print $2}')
  echo "| Pool Member | $pool/$member |"
done
for node in "${zero_nodes[@]}"; do
  echo "| Node | $node |"
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
for vs in "${zero_vs[@]}"; do
  echo "tmsh delete ltm virtual $vs"
done
for pm in "${zero_pms[@]}"; do
  pool=$(echo $pm | awk '{print $1}')
  member=$(echo $pm | awk '{print $2}')
  echo "tmsh modify ltm pool $pool members delete { $member }"
done
for node in "${zero_nodes[@]}"; do
  echo "tmsh delete ltm node $node"
done
for irule in "${zero_irules[@]}"; do
  echo "tmsh delete ltm rule $irule"
done
for pool in "${unreferenced_pools[@]}"; do
  echo "tmsh delete ltm pool $pool"
done

