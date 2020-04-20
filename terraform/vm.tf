resource "vsphere_virtual_machine" "`VMNAME`" {
  name             = "`VMNAME`"
  resource_pool_id = data.vsphere_resource_pool.pool.id
  datastore_id     = data.vsphere_datastore.datastore.id


  num_cpus                   = 1
  memory                     = 2048
  wait_for_guest_net_timeout = 0
  guest_id                   = data.vsphere_virtual_machine.template.guest_id
  scsi_type                  = data.vsphere_virtual_machine.template.scsi_type
  nested_hv_enabled          = true

  network_interface {
    network_id   = data.vsphere_network.mgmt_lan.id
    adapter_type = data.vsphere_virtual_machine.template.network_interface_types[0]
  }

  disk {
    label            = "disk0"
    size             = var.vsphere_vm_disk_size
    eagerly_scrub    = data.vsphere_virtual_machine.template.disks.0.eagerly_scrub
    thin_provisioned = data.vsphere_virtual_machine.template.disks.0.thin_provisioned
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.template.id
  }
}

output "ip_addr_`VMNAME`" {
  value = vsphere_virtual_machine.`VMNAME`.*.default_ip_address
}