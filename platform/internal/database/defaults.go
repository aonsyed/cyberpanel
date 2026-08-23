package database

import "net/netip"

func DefaultLocalInstance()(DatabaseInstance,error){
	instanceID,err:=NewResourceID("mariadb-local");if err!=nil{return DatabaseInstance{},err};serviceID,err:=NewResourceID("service-mariadb");if err!=nil{return DatabaseInstance{},err};policyID,err:=NewResourceID("mariadb-local-network");if err!=nil{return DatabaseInstance{},err}
	status:=ResourceStatus{Lifecycle:LifecycleReady,Health:HealthHealthy,Reconciliation:ReconciliationInSync,ObservedGeneration:1}
	instance:=DatabaseInstance{Metadata:Metadata{ID:instanceID,Generation:1,Status:status},Placement:PlacementLocal,Version:MariaDBVersion{Major:10,Minor:11},LocalServiceRef:serviceID,NetworkPolicyID:policyID,Capacity:InstanceCapacity{StorageBytes:1<<40,MemoryBytes:8<<30,MaxConnections:500}}
	return instance,instance.Validate()
}

func DefaultLocalNetworkPolicy()(NetworkAccessPolicy,error){
	instance,err:=DefaultLocalInstance();if err!=nil{return NetworkAccessPolicy{},err};policy:=NetworkAccessPolicy{Metadata:Metadata{ID:instance.NetworkPolicyID,Generation:1,Status:ResourceStatus{Lifecycle:LifecycleReady,Health:HealthHealthy,Reconciliation:ReconciliationInSync,ObservedGeneration:1}},InstanceID:instance.ID,Interfaces:[]NetworkInterface{InterfaceLoopback},AllowedCIDRs:[]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"),netip.MustParsePrefix("::1/128")},TLS:TLSRequired,Verification:VerifyLocalEndToEnd};return policy,policy.Validate()
}
