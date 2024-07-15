path "sys/namespaces" {
  capabilities = ["list"]
}

path "+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/+/+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/+/+/+/sys/namespaces" {
  capabilities = ["list"]
}

path "sys/auth" {
  capabilities = ["read"]
}

path "+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/auth" {
  capabilities = ["read"]
}

path "sys/mounts" {
  capabilities = ["read"]
}

path "+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/mounts" {
  capabilities = ["read"]
}