#!/bin/bash

# 1. 检查privileged特权容器
# ./scan-image.sh privileged

# 2. 检查root用户容器
# ./scan-image.sh root

# 3. 检查包含调试/嗅探工具的镜像
# ./scan-image.sh tools

# 4. 检查环境变量中含有敏感信息的容器
# ./scan-image.sh env

# 5. 检查配置文件/证书文件权限不是600的镜像
# ./scan-image.sh permission

# 6. 检查挂载k8s token的容器
# ./scan-image.sh token

# 7. 检查容器本身的证书私钥 以及 挂载的私钥是否加密
# ./scan-image.sh openssl

# 8. 检查系统的无属组文件
# 不传path默认扫描 / 目录下的文件，不扫描 /proc 和 /sys
# ./scan-image.sh noowner ${path}

# 9. 镜像无用文件裁剪扫描
# ./scan-image.sh compress

# 10. 镜像cve扫描
# 需要将待扫描的镜像清单写入 ./images.txt 中，每个镜像单独一行
# ./scan-image.sh image

# 11. 清除无用镜像
# ./scan-image.sh clean

# 12. 扫描securityContext
# ./scan-image.sh security_context


if [[ ${debug:-flase} = "true" ]]; then
  set -x
fi

hostname=$(sh -c hostname)
node_ip=$(kubectl get node -o wide | grep "$hostname" | awk '{print $6}')
echo "node_ip: $node_ip"

if [ "$(ps -ef|grep kubelet |grep isulad.sock)" != "" ];then
  runtime_builtin=isula
else
  runtime_builtin=docker
fi
RUNTIME=${RUNTIME:-$runtime_builtin}
DOCKER_IMAGE_LS="docker image ls"
DOCKER_PS="docker ps"
DOCKER_INSPECT="docker inspect"
DOCKER_EXEC="docker exec"
DOCKER_RMI="docker rmi"
DOCKER_PULL="docker pull"

if [ $RUNTIME = "isula" ]; then
  DOCKER_IMAGE_LS="isula images"
  DOCKER_PS="isula ps"
  DOCKER_INSPECT="isula inspect"
  DOCKER_EXEC="isula exec"
  DOCKER_RMI="isula rmi"
  DOCKER_PULL="isula pull"
fi

function clean_exited_container() {
  if [ "$(command -v docker)" != "" ]; then
    for container in `docker ps -a | grep Exited | awk '{print $1}'`; do
      echo "clean docker container $container"
      docker rm $container
      echo ""
    done
  fi
  if [ "$(command -v isula)" != "" ]; then
    for container in `isula ps -a | grep Exited | awk '{print $1}'`; do
      echo "clean isula container $container"
      isula rm $container
      echo ""
    done
  fi
}

function scan_privileged() {
  $DOCKER_PS --quiet -a | xargs $DOCKER_INSPECT --format='{{index .RepoTags 0}} {{.HostConfig.Privileged}}' 2>/dev/null | grep true | awk '{print $1}'
}

function scan_root() {
  containers=$($DOCKER_PS | awk 'NR!=1 {print $1}')
  # shellcheck disable=SC2154
  #  echo $containers
  echo "ContainerId | ImageId | RepoTags"
  # shellcheck disable=SC2068
  for container in ${containers[@]}; do
    # echo $image
    # shellcheck disable=SC2046
    # shellcheck disable=SC1066
    user=$($DOCKER_EXEC -i "$container" whoami 2>/dev/null)
    if [ $? != 0 ]; then
      continue
    fi
    if [ "$user" = "root" ]; then
      container_info=$($DOCKER_PS --format="{{.ID}}  {{.Image}}  {{.Names}}" | grep "$container" | awk '{print $1,$2}')
      imageid=$($DOCKER_PS | grep "$container" | awk '{print $2}')
      if [ "$RUNTIME" = "docker" ]; then
        image_info=$($DOCKER_INSPECT --format="{{index .RepoTags 0}}" $imageid 2>/dev/null)
      elif [ "$RUNTIME" = "isula" ]; then
        image_info=$($DOCKER_INSPECT -f {{.image.repo_tags}} $imageid 2>/dev/null | grep -Eo '[a-z\w]+[a-z0-9\w]+[^"]*')
        if [[ "$image_info" = "" ]]; then
          image_info=$($DOCKER_INSPECT -f {{.image.id}} $imageid)
        fi
      else
        image_info=""
      fi
      echo "$container_info $image_info"
    fi
  done
}

function scan_tools() {
  output="${1:-tools.txt}"
  # tools=("tcpdump" "sniffer" "wireshark" "Netcat" "gdb" "strace" "readelf" "cpp" "gcc" "dexdump" "mirror" "JDK" "netcat")
  tools=("tcpdump" "sniffer" "wireshark" "Netcat" "strace" "readelf" "Nmap" "gdb" "cpp" "gcc" "jdk" "javac" "make" "binutils" "flex" "glibc-devel" "gcc-c++" "Id" "lex" "rpcgen" "objdump" "eu-readelf" "eu-objdump" "dexdump" "mirror" "lua" "Perl" "nc" "ethereal" "aplay" "arecord" "vnstat" "vnStatsvg" "nload" "atop" "iftop")
  if [ $RUNTIME = "docker" ]; then
    echo "Tool | Id | RepoTags"
  else
    echo "Tool | Image | Path"
  fi
  # shellcheck disable=SC2068
  for tool in ${tools[@]}; do

    if [ $RUNTIME = "docker" ]; then
      # shellcheck disable=SC2046
      # shellcheck disable=SC1066
      overlays=$(find /var/lib/docker 2>/dev/null | grep -i "/${tool}$" | awk -F/ '{print $6}' | uniq | sort | grep -v "^$")
      if [ "$overlays" = "" ]; then
        continue
      fi

      $DOCKER_IMAGE_LS | awk '{if (NR>1){print $3}}' |
        xargs $DOCKER_INSPECT --format '{{.Id}}, {{index .RepoTags 0}}, {{.GraphDriver.Data}}' 2>/dev/null |
        grep -E $(echo $overlays | sed 's/ /|/g') | awk -F, '{printf("%s %s %s\n", "'$tool'", $1, $2)}' 2>/dev/null
#      if [ "$result" != "" ]; then
#        echo -e "$result" >>$output
#        echo -e $result
#      fi
    elif [ $RUNTIME = "isula" ]; then
      layer_dirs=$(find /var/lib/isulad/storage/overlay/ | grep diff$ | xargs -I {} find {} | grep -i "/${tool}$" | awk -F/ '{print $7}' | uniq | sort | grep -v "^$")
      if [ "$layer_dirs" = "" ]; then
        continue
      fi
      # shellcheck disable=SC2001
      layer_egrep=$(echo $layer_dirs | sed 's/ /|/g')

      root_dir=/var/lib/isulad/storage/overlay-images
      image_files=$(ls -l $root_dir | awk '{if (NR>1) print $9}')
      # shellcheck disable=SC2034
      for image_file in ${image_files[@]}; do
        image_dir=$root_dir/$image_file
        # shellcheck disable=SC2002
        image_json=$(cat "${image_dir}/images.json")
        image_id=$(echo $image_json | grep -Eo '"id": [^,]+' | awk '{print $2}' | sed 's/"//g')
        image_name=$(echo ${image_json} | grep -Eo '"names":[^,]+' | sed 's/ //g' | awk -F '"' '{print $4}')
        image_layer_file=$(find $image_dir | grep "=")
        layer_hashs=$(cat $image_layer_file | grep -Eo '"(sha256:[a-f0-9]+)"' | grep -E "'"${layer_egrep}"'")
        if [ "$layer_hashs" != "" ]; then
          for layer_hash in ${layer_hashs[@]}; do
            if [ "$image_name" != "" ]; then
              echo "$tool $image_name /var/lib/isulad/storage/overlay/$(echo $layer_hash | sed 's/"//g' | awk -F: '{print $2}')/diff/"
            else
              echo "$tool $image_id /var/lib/isulad/storage/overlay/$(echo $layer_hash | sed 's/"//g' | awk -F: '{print $2}')/diff/"
            fi
          done
        fi
      done
    fi
  done
  echo "output: $output"
}

function scan_env() {
  containers=$($DOCKER_PS | awk 'NR!=1 {print $1}')
  # shellcheck disable=SC2068
  for container in ${containers[@]}; do
    container_info=$($DOCKER_PS --format="{{.ID}}  {{.Image}}  {{.Names}}" | grep "$container")
    envs=$($DOCKER_INSPECT --format="{{.Config.Env}}" "$container")
    # shellcheck disable=SC2046
    if [ "$(echo "$envs" | grep -i "password\|secret\|token")" = "" ]; then
      continue
    fi
    imageid=$($DOCKER_PS | grep "$container" | awk '{print $2}')

    if [ "$RUNTIME" = "docker" ]; then
      image_info=$($DOCKER_INSPECT --format="{{index .RepoTags 0}}" $imageid 2>/dev/null)
    elif [ "$RUNTIME" = "isula" ]; then
      image_info=$($DOCKER_INSPECT -f {{.image.repo_tags}} $imageid 2>/dev/null | grep -Eo '[a-z\w]+[a-z0-9\w]+[^"]*')
      if [[ "$image_info" = "" ]]; then
        image_info=$($DOCKER_INSPECT -f {{.image.id}} $imageid)
      fi
    else
      image_info=""
    fi
    # shellcheck disable=SC2181
    if [ "$image_info" != "" ]; then
      echo "$container_info $image_info $envs"
    else
      echo "$container_info $imageid $envs"
    fi
  done
}

function scan_permission() {
  output="${1:-permission.txt}"
  hostname=$(sh -c hostname)
  images=$($DOCKER_IMAGE_LS | awk 'NR!=1 {print $3}')
  echo "hostname | image | permission | file"
  # shellcheck disable=SC2068
  for image in ${images[@]}; do

    if [ "$RUNTIME" = "docker" ]; then
      # shellcheck disable=SC2086
      repo_tags=$($DOCKER_INSPECT --format="{{index .RepoTags 0}}" $image 2>/dev/null)
      result=$($DOCKER_INSPECT -f {{.GraphDriver.Data.UpperDir}} "${image}" | awk -F ":" 'BEGIN{OFS="\n"}{ for(i=1;i<=NF;i++)printf("%s\n",$i)}' |
        xargs -I {} find {} ! -perm 600 -name "*.crt" -o ! -perm 600 -name "*.pem" -o ! -perm 640 -name "*.conf" -o ! -perm 640 "*.properties" 2>/dev/null |
        xargs -I {} ls -l {} | awk -F ' ' '{if (NR>1) {printf("%s %s %s %s %s\n", "'$hostname'", "'$image'", "'$repo_tags'", $1, $9)}}' 2>/dev/null)
      if [ "$result" != "" ]; then
        echo "$result"
        echo "$result" >>$output
      fi
      # shellcheck disable=SC2086
      result=$($DOCKER_INSPECT -f {{.GraphDriver.Data.LowerDir}} "${image}" | awk -F ":" 'BEGIN{OFS="\n"}{ for(i=1;i<=NF;i++)printf("%s\n",$i)}' |
        xargs -I {} find {} ! -perm 600 -name "*.crt" -o ! -perm 600 -name "*.pem" -o ! -perm 640 -name "*.conf" -o ! -perm 640 "*.properties" 2>/dev/null |
        xargs -I {} ls -l {} | awk -F ' ' '{if (NR>1) {printf("%s %s %s %s %s\n", "'$hostname'", "'$image'", "'$repo_tags'", $1, $9)}}' 2>/dev/null)
      if [ "$result" != "" ]; then
        echo "$result"
        echo "$result" >>$output
      fi
    elif [ "$RUNTIME" = "isula" ]; then
      repo_tags=$($DOCKER_INSPECT -f {{.image.repo_tags}} $image 2>/dev/null | grep -Eo '[a-z\w]+[a-z0-9\w]+[^"]*')
      result=$($DOCKER_INSPECT -f {{.image.Spec.rootfs.diff_ids}} "${image}" |
        grep -Eo '(sha256:[a-f0-9]+)' | awk -F: '{printf("/var/lib/isulad/storage/overlay/%s\n", $2)}' |
        xargs -I {} find {} ! -perm 600 -name "*.crt" -o ! -perm 600 -name "*.pem" -o ! -perm 640 -name "*.conf" ! -perm 640 "*.properties" 2>/dev/null |
        xargs -I {} ls -l {} | awk -F ' ' '{if (NR>1) {printf("%s %s %s %s %s\n", "'$hostname'", "'$image'", "'$repo_tags'", $1, $9)}}' 2>/dev/null)
      if [ "$result" != "" ]; then
        echo "$result"
        echo "$result" >>$output
      fi
    fi
  done
  echo "output: $output"
}

function scan_token() {
  token_dirs=$(find / -name "kube-api-access-*" 2>/dev/null)
  hostname=$(sh -c hostname)
  node_ip=$(kubectl get node -o wide | awk '{if (NR==2){print $6}}')
  if [ "$node_ip" = "" ]; then
    return
  fi
  server=${server:-https://$node_ip:6443}
  echo "hostname | token | containers"
  # shellcheck disable=SC2068
  for token_dir in ${token_dirs[@]}; do
    token="$token_dir/token"
    container_dir=$(echo "$token_dir" | awk -F "/" '{for(i=1;i<7;i++) printf("%s/",$i)}')
    # shellcheck disable=SC2012
    containers=$(ls "$container_dir"/containers | awk '{for(i=1;i<4;i++) if($i!="")printf("%s ",$i)}')
    echo "$hostname $token $containers"
    # shellcheck disable=SC2046
    kubectl --token=$(cat "$token") --kubeconfig=/dev/null --server="${server}" --insecure-skip-tls-verify=true auth can-i --list
  done
}

function scan_openssl() {
  hostname=$(sh -c hostname)
  echo " hostname | image | tag | container | file"
  containers=$($DOCKER_PS | awk 'NR!=1 {print $1}')
  # shellcheck disable=SC2068
  for container in ${containers[@]}; do
    # shellcheck disable=SC2046
    # shellcheck disable=SC1066
    container_info=$($DOCKER_PS --format="{{.ID}}  {{.Image}}  {{.Names}}" | grep "$container")
    image=$($DOCKER_PS | grep "$container" | awk '{print $2}')
    if [ "$RUNTIME" = "docker" ]; then
      repo_tags=$($DOCKER_INSPECT --format="{{index .RepoTags 0}}" $image 2>/dev/null)
      mounts=$($DOCKER_INSPECT --format='{{range .Mounts}}{{printf "%s\n" .Source}}{{end}}' "$container")
    elif [ "$RUNTIME" = "isula" ]; then
      repo_tags=$($DOCKER_INSPECT --format="{{.image.repo_tags}}" $image 2>/dev/null | grep -Eo '[a-z\w]+[a-z0-9\w]+[^"]*')
      mounts=$($DOCKER_INSPECT --format="{{.Mounts}}" $container | grep -Eo '("Source":[^,]*)' | awk -F: '{print $2}' | sed 's/ //g')
    else
      repo_tags=""
      mounts=""
    fi

    # shellcheck disable=SC2034
    for mount_dir in ${mounts[@]}; do
      if [[ $mount_dir = "/proc" ]] || [[ $mount_dir = "/sys" ]] || [[ $mount_dir = "/" ]]; then
        continue
      fi
      mount_files=$(find "$mount_dir" -type f -name "*.key")
      for mount_file in ${mount_files[@]}; do
        #        is_encrypted=$(grep -c "BEGIN ENCRYPTED PRIVATE KEY" "$mount_file")
        is_private_key=$(grep -c "PRIVATE KEY" "$mount_file")
        is_encrypted=$(grep -c "ENCRYPTED" "$mount_file")
        if [[ $is_private_key = '2' ]]; then
          if [[ "$is_encrypted" = '0' ]]; then
            echo "$hostname $image $repo_tags $container $mount_file"
          fi
        fi
      done
    done

    upper_files=$($DOCKER_INSPECT -f {{.GraphDriver.Data.UpperDir}} "$container" | sed 's/:/\n/g' | xargs -I {} find {} -type f -name "*.key" 2>/dev/null)
    if [[ $upper_files != "" ]]; then
      for upper_file in ${upper_files[@]}; do
        is_private_key=$(grep -c "PRIVATE KEY" "$mount_file")
        is_encrypted=$(grep -c "ENCRYPTED" "$mount_file")
        if [[ $is_private_key = '2' ]]; then
          if [[ "$is_encrypted" = '0' ]]; then
            echo "$hostname $image $repo_tags $container $upper_file"
          fi
        fi
      done
    fi
    lower_files=$($DOCKER_INSPECT -f {{.GraphDriver.Data.LowerDir}} "$container" | sed 's/:/\n/g' | xargs -I {} find {} -type f -name "*.key" 2>/dev/null)
    if [[ $lower_files != "" ]]; then
      for lower_file in ${lower_files[@]}; do
        is_private_key=$(grep -c "PRIVATE KEY" "$mount_file")
        is_encrypted=$(grep -c "ENCRYPTED" "$mount_file")
        if [[ $is_private_key = '2' ]]; then
          if [[ "$is_encrypted" = '0' ]]; then
            echo "$hostname $image $repo_tags $container $lower_file"
          fi
        fi
      done
    fi

  done
}

function scan_noowner() {
  dir=${1:-/}
  # shellcheck disable=SC2038
  find $dir -xdev \( -nouser -o -nogroup \) \( ! -path "/proc" -o ! -path "/sys" \) -type f -print | xargs -I {} ls -l {}
}

function scan_compress() {
  imageids=$($DOCKER_IMAGE_LS | awk 'NR!=1 {print $3}')
  hostname=$(sh -c hostname)
  # shellcheck disable=SC2068
  for imageid in ${imageids[@]}; do
    tools=("ssl" "gcc" "gdb" "cert.pem")
    tag=$(docker inspect -f "{{index .RepoTags 0}}" $imageid 2>/dev/null)
    if [ "$tag" == "" ]; then
      show_tag=$imageid
    else
      show_tag=$tag
    fi
    # shellcheck disable=SC2068
    for tool in ${tools[@]}; do
      $DOCKER_INSPECT -f {{.GraphDriver.Data.UpperDir}} $imageid | sed 's/:/\n/g' |
        xargs find 2>>/dev/null| grep $tool | awk '{printf("%s %s %s\n", "'$show_tag'", "'$tool'", $1)}'
      $DOCKER_INSPECT -f {{.GraphDriver.Data.LowerDir}} $imageid | sed 's/:/\n/g' |
              xargs find 2>>/dev/null| grep $tool | awk '{printf("%s %s %s\n", "'$show_tag'", "'$tool'", $1)}'
    done
  done
}

function scan-fs() {
  input_dir=$1
  if [ "$input_dir" = "" ]; then
    echo "Please input scan dir: ./scan-image.sh fs ./images/"
    exit 1
  fi
  tmp_parent_dir=$(dirname $input_dir)
  tmp_dir=$tmp_parent_dir/$(basename $input_dir)_tmp
  if [ ! -d $tmp_dir ]; then
    mkdir -p $tmp_dir
    echo "generated tmp_dir: $tmp_dir"
  else
    echo "tmp_dir already existed: $tmp_dir"
  fi

  # untar file to tmp_dir
  untar-files $input_dir $tmp_dir
}

function untar-files() {
  echo "untar-files"
#  input=$1
#  tmp_dir=$2
#
#  ext=.tar
#  tar_files=$(find $input -name "*$ext" -type f)
#  # shellcheck disable=SC2068
#  for tar_file in ${tar_files[@]}; do
#    #    echo $tar_file
#    tar_file_dir=$tmp_dir/$(basename $tar_file $ext)
#    if [ ! -d $tar_file_dir ]; then
#      mkdir $tar_file_dir
#    fi
#
#    tar -xf $tar_file -C $tar_file_dir
#    echo "tar -xf $tar_file -C $tar_file_dir"
#    echo $tar_file_dir
#  done
#
#  ext=.tar.gz
#  tar_files=$(find $input -name "*$ext" -type f)
#  # shellcheck disable=SC2068
#  for tar_file in ${tar_files[@]}; do
#    #    echo $tar_file
#    tar_file_dir=$tmp_dir/$(basename $tar_file $ext)
#    if [ ! -d $tar_file_dir ]; then
#      mkdir $tar_file_dir
#    fi
#
#    tar -zxf $tar_file -C $tar_file_dir
#    echo "tar -zxf $tar_file -C $tar_file_dir"
#    echo $tar_file_dir
#  done
#
#  ext=.tar
#  while (("$(find $tmp_dir -name "*$ext" -type f | wc -l)" > 0)); do
#    tar_files=$(find $tmp_dir -name "*$ext" -type f)
#    # shellcheck disable=SC2068
#    for tar_file in ${tar_files[@]}; do
#      #      echo $tar_file
#      tar_file_dir=$(dirname $tar_file)/$(basename $tar_file $ext)
#      if [ ! -d $tar_file_dir ]; then
#        mkdir $tar_file_dir
#      fi
#      tar -xf $tar_file -C $tar_file_dir
#      echo "tar -xf $tar_file -C $tar_file_dir"
#      rm $tar_file
#    done
#  done
#
#  ext=.tar.gz
#  while (("$(find $tmp_dir -name "*$ext" -type f | wc -l)" > 0)); do
#    tar_files=$(find $tmp_dir -name "*$ext" -type f)
#    # shellcheck disable=SC2068
#    for tar_file in ${tar_files[@]}; do
#      #      echo $tar_file
#      tar_file_dir=$(dirname $tar_file)/$(basename $tar_file $ext)
#      if [ ! -d $tar_file_dir ]; then
#        mkdir $tar_file_dir
#      fi
#      tar -zxf $tar_file -C $tar_file_dir
#      echo "tar -zxf $tar_file -C $tar_file_dir"
#      rm $tar_file
#    done
#  done
}

function scan_image() {
  image=$1
  output=$2
  dirs=(
    LowerDir
    UpperDir
  )
  # shellcheck disable=SC2068
  for dir in ${dirs[@]}; do
    # shellcheck disable=SC1083
    overlays=$($DOCKER_INSPECT -f {{.GraphDriver.Data.$dir}} $image 2>/dev/null| sed 's/:/\n/g' | sed 's/<no value>//g')
    # shellcheck disable=SC2068
    for overlay in ${overlays[@]}; do
      if [ "$overlay" == "" ]; then
        continue
      fi
      ret=$(trivy rootfs $overlay -q -f json)
      results=$(echo $ret|jq .Results)
      if [ "$results" != "null" ]; then
        if [ "$(echo $results | jq '.[].Vulnerabilities')" != "null" ]; then
          echo $results | jq '.[]|select(.Vulnerabilities|length >0) | .Vulnerabilities | .[] | ["'$image'",.VulnerabilityID,.PkgName,.PkgPath,.CVSS.ghsa.V3Score,.CVSS.nvd.V3Score] | join(",")' | sed 's/\"//g' >> $output
        fi
      fi
    done
  done
}

function scan_cve() {
  if [ ! -f "./images.txt" ]; then
    echo "Please enter the image in ./images.txt."
    exit 1
  fi
  images=$(cat images.txt)
  output=result.csv
  echo "image,cve,pkg_name,pkg_path,ghsa_score,nvd_score" > $output
  # shellcheck disable=SC2068
  for image in ${images[@]}; do
    $DOCKER_PULL $image
    scan_image $image $output
  done
  cat $output
}

function scan_security_context() {
  clean_exited_container
  opts=(
    no-new-privileges
  )
  for container in `$DOCKER_PS -q -a`; do
    security_opt=$($DOCKER_INSPECT -f '{{.Id}} {{.Name}} {{.HostConfig.SecurityOpt}}' $container)
    need_fix=false
    # shellcheck disable=SC2068
    for opt in ${opts[@]}; do
      if [ "$(echo $security_opt | grep $opt)" = "" ]; then
        need_fix=true
      fi
    done
    if [ "$need_fix" = "true" ]; then
      echo $security_opt
      echo ""
    fi
  done
}

function scan_host_network() {
  clean_exited_container
  for container in `$DOCKER_PS -q -a`; do
    host_network=$($DOCKER_INSPECT -f '{{.Id}} {{.Name}} {{.HostConfig.NetworkMode}}' $container)
    if [ "$(echo $host_network | grep host)" != "" ]; then
      echo $host_network
      echo ""
    fi
  done
}

function scan_host_pid() {
  clean_exited_container
  for container in `$DOCKER_PS -q -a`; do
    host_network=$($DOCKER_INSPECT -f '{{.Id}} {{.Name}} {{.HostConfig.PidMode}}' $container)
    if [ "$(echo $host_network | grep host)" != "" ]; then
      echo $host_network
      echo ""
    fi
  done
}

function scan_uts_ns() {
  clean_exited_container
  for container in `$DOCKER_PS -q -a`; do
    host_network=$($DOCKER_INSPECT -f '{{.Id}} {{.Name}} {{.HostConfig.UTSMode}}' $container)
    if [ "$(echo $host_network | grep host)" != "" ]; then
      echo $host_network
      echo ""
    fi
  done
}

function clean() {
  docker_cmd=$(command -v docker)
  isula_cmd=$(command -v isula)
  if [ "$docker_cmd" != "" ]; then
    docker system prune -a -f
  fi
  if [ "$isula_cmd" != "" ]; then
    images=$($DOCKER_IMAGE_LS | awk 'NR!=1 {print $3}')
    # shellcheck disable=SC2068
    for image in ${images[@]}; do
      repo_tags=$($DOCKER_INSPECT --format="{{.image.repo_tags}}" $image 2>/dev/null | grep -Eo '[a-z\w]+[a-z0-9\w]+[^"]*')
      if [[ "$repo_tags" = "" ]]; then
        $DOCKER_RMI $image
        echo "remove ${image}"
      fi
    done
    isula images | awk 'NR!=1 {print $3}' | xargs isula rmi
  fi
  history -c
}

function utils {
  if [ ${debug:-false} = true ]; then
    set -x
  fi

  CMD=$1
  if [ "$CMD" = "privileged" ]; then
    scan_privileged
  elif [ "$CMD" = "root" ]; then
    scan_root
  elif [ "$CMD" = "tools" ]; then
    scan_tools $2
  elif [ "$CMD" = "env" ]; then
    scan_env
  elif [ "$CMD" = "permission" ]; then
    scan_permission $2
  elif [ "$CMD" = "token" ]; then
    scan_token
  elif [ "$CMD" = "openssl" ]; then
    scan_openssl
  elif [ "$CMD" = "noowner" ]; then
    scan_noowner $2
  elif [ "$CMD" = "compress" ]; then
    scan_compress
  elif [ "$CMD" = "image" ]; then
#    scan-fs $2
    scan_cve $2
  elif [ "$CMD" = "security_context" ]; then
    scan_security_context
  elif [ "$CMD" = "host_network" ]; then
    scan_host_network
  elif [ "$CMD" = "host_pid" ]; then
    scan_host_pid
  elif [ "$CMD" = "uts_ns" ]; then
    scan_uts_ns
  elif [ "$CMD" = "clean" ]; then
    clean
  elif [ "$CMD" = "-h" ] ||  [ "$CMD" = "" ]; then
    echo "scan-image.sh"
    echo "<command>:"
    echo "    privileged"
    echo "    root"
    echo "    tools"
    echo "    env"
    echo "    permission"
    echo "    token"
    echo "    openssl"
    echo "    noowner"
    echo "    security_context"
    echo "    host_network"
    echo "    host_pid"
    echo "    uts_ns"
    echo "    clean"
    echo "    compress"
    echo "    image"
  fi
  if [ "$CMD" != "" ]; then
    echo "Finish scan $CMD"
  fi
}

utils $1 $2
