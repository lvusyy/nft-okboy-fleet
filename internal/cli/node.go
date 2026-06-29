package cli

import (
	"flag"
	"fmt"
	"strconv"

	"nft-okboy-fleet/internal/db"
	"nft-okboy-fleet/internal/firewall"
)

// CmdNodeAdd registers an edge node and prints its enrollment token ONCE. The hub
// stores only sha256(token); the agent presents the raw token as a bearer.
func CmdNodeAdd(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("node-add", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: node-add <name>")
	}
	name := fs.Arg(0)
	if !firewall.ValidName(name) {
		return fmt.Errorf("invalid node name %q (allowed: alphanumeric start, then [A-Za-z0-9_-], max 64)", name)
	}
	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()

	token, err := genSecret()
	if err != nil {
		return err
	}
	if _, err := d.CreateNode(name, db.HashToken(token)); err != nil {
		return fmt.Errorf("create node %q: %w", name, err)
	}
	audit(d, "node_add", name, "")
	fmt.Printf("Created node '%s'.\n\n", name)
	fmt.Printf("Enrollment token (shown ONCE — configure the agent with it):\n\n  %s\n\n", token)
	fmt.Printf("On the node, run the agent:\n  okboy agent --hub https://<hub>/ --node %s --token %s\n", name, token)
	return nil
}

// CmdNodeList prints the registered nodes: id, name, last-seen.
func CmdNodeList(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("node-list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()
	nodes, err := d.ListNodes()
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		fmt.Println("No nodes registered.")
		return nil
	}
	fmt.Printf("%4s  %-20s  %s\n", "ID", "Name", "Last Seen")
	for _, n := range nodes {
		fmt.Printf("%4d  %-20s  %s\n", n.ID, n.Name, fmtKnock(n.LastSeen))
	}
	return nil
}

// CmdNodeDel deletes a node; its group targets cascade away via the FK.
func CmdNodeDel(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("node-del", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: node-del <name>")
	}
	name := fs.Arg(0)
	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()
	node, err := d.GetNodeByName(name)
	if err != nil {
		return err
	}
	if node == nil {
		fmt.Printf("Node '%s' not found.\n", name)
		return nil
	}
	if err := d.DeleteNode(node.ID); err != nil {
		return err
	}
	audit(d, "node_del", name, "")
	fmt.Printf("Deleted node '%s' (and its group targets).\n", name)
	return nil
}

// CmdGroupTarget manages a group's per-node (port, proto) targets:
//
//	group-target add <group> <node> <port> [--proto tcp]
//	group-target list
//	group-target del <group> <node>
func CmdGroupTarget(cfgPath string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: group-target <add|list|del> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return groupTargetAdd(cfgPath, rest)
	case "list":
		return groupTargetList(cfgPath, rest)
	case "del", "rm", "remove":
		return groupTargetDel(cfgPath, rest)
	default:
		return fmt.Errorf("unknown group-target subcommand %q (add|list|del)", sub)
	}
}

func groupTargetAdd(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("group-target add", flag.ContinueOnError)
	proto := fs.String("proto", "tcp", "Protocol (default: tcp)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 3 {
		return fmt.Errorf("usage: group-target add <group> <node> <port> [--proto tcp]")
	}
	groupName, nodeName := fs.Arg(0), fs.Arg(1)
	port, err := strconv.Atoi(fs.Arg(2))
	if err != nil {
		return fmt.Errorf("port must be an integer: %q", fs.Arg(2))
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range (1-65535)", port)
	}
	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()
	group, err := d.GetGroupByName(groupName)
	if err != nil {
		return err
	}
	if group == nil {
		return fmt.Errorf("group %q not found", groupName)
	}
	node, err := d.GetNodeByName(nodeName)
	if err != nil {
		return err
	}
	if node == nil {
		return fmt.Errorf("node %q not found", nodeName)
	}
	if err := d.AddGroupTarget(group.ID, node.ID, port, *proto); err != nil {
		return err
	}
	audit(d, "group_target_add", groupName+"@"+nodeName, fmt.Sprintf("port=%d proto=%s", port, *proto))
	fmt.Printf("Group '%s' now targets node '%s' at %d/%s.\n", groupName, nodeName, port, *proto)
	return nil
}

func groupTargetList(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("group-target list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()
	targets, err := d.ListGroupTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("No group targets defined.")
		return nil
	}
	fmt.Printf("%-20s  %-20s  %5s  %s\n", "Node", "Group", "Port", "Proto")
	for _, t := range targets {
		fmt.Printf("%-20s  %-20s  %5d  %s\n", t.Node, t.Group, t.Port, t.Proto)
	}
	return nil
}

func groupTargetDel(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("group-target del", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: group-target del <group> <node>")
	}
	groupName, nodeName := fs.Arg(0), fs.Arg(1)
	_, d, err := loadCfgDB(cfgPath)
	if err != nil {
		return err
	}
	defer d.Close()
	group, err := d.GetGroupByName(groupName)
	if err != nil {
		return err
	}
	if group == nil {
		return fmt.Errorf("group %q not found", groupName)
	}
	node, err := d.GetNodeByName(nodeName)
	if err != nil {
		return err
	}
	if node == nil {
		return fmt.Errorf("node %q not found", nodeName)
	}
	if err := d.RemoveGroupTarget(group.ID, node.ID); err != nil {
		return err
	}
	audit(d, "group_target_del", groupName+"@"+nodeName, "")
	fmt.Printf("Removed target: group '%s' no longer targets node '%s'.\n", groupName, nodeName)
	return nil
}
