variable "vsphere_server" {
  default = "10.50.71.4"
}
variable "vsphere_datacenter_name" {
  default = "MathCSDatacenter"

}

variable "vsphere_datastore_name" {
  default = "mathcsdata01"

}
variable "vsphere_resource_pool_name" {

  default = "MathCSResearch"
}

variable "vsphere_network_name" {

  default = "MathCS_10.50.71/24"
}
variable "vsphere_vm_name" {

  default = "test_vm_hans"
}
variable "vsphere_vm_guest_id" {

  default = "ubuntu64Guest"
}
variable "vsphere_vm_disk_size" {
  default = 20
}

variable "vsphere_vm_disk_label" {
  default = "test_vm_hans_disk.vmdk"
}

variable "vsphere_18_04_template_name" {
  default = "ubuntu_18.04.1_terraform"
}

variable "vsphere_user" {}
variable "vsphere_password" {}

