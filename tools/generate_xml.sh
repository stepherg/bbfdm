#!/bin/sh

# Copyright (C) 2020 iopsys Software Solutions AB
# Author: Omar Kallel <omar.kallel@pivasoftware.com>
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

# VARIABLES ####################################################################################################
obj_look_obj_child_list=""
obj_look_param_child_list=""

# FUNCTIONS ####################################################################################################
set_node_name() { 
	echo ${1}
}

set_obj_object_child() { 
	echo "${1},${2}"
}

set_obj_object_line() {
	echo "object, ${1}, root, ${2}"
}

set_obj_param_child() { 
	echo "${1},${2}"
}
set_obj_param_line() { 
	echo "parameter, ${1}, root, ${2}"
}

set_obj_instance_line(){
	echo "instance, , root, ${1}"
}

set_objs_child_instance_name(){
	echo "${1}.${2}"
}

set_prms_child_instance_name(){
	echo "${1}.${2}"
}

get_param_type(){
	ptype=$1
	case "$ptype" in
		"DMT_STRING" )
			echo "string"
			;;
		"DMT_UNINT" )
			echo "unsignedInt"
			;;
		"DMT_TIME" )
			echo "dateTime"
			;;
		"DMT_BOOL" )
			echo "boolean"
			;;
		"DMT_LONG" )
			echo "long"
			;;
		"DMT_INT" )
			echo "int"
			;;
		"DMT_HEXBIN" )
			echo "hexbin"
			;;
	esac
	
}

get_leaf_obj_line_number(){
	echo `grep -nE DMOBJ\|DMLEAF $1 | grep -v UPNP | cut -f1 -d: | tr "\n" " "`
}

add_item_to_list(){
	item="$1"
	list="$2"
	length=${#list}
	if [ $length == 0 ]; then
		list="$item"
	else
		list="$list $item"
	fi
	echo "$list"
}

remove_item_from_list(){
	item="$1"
	list="$2"
	new_list=""
	for i in $list; do
		if [ "$i" == "$item" ]; then
			continue
		fi
		new_list=`add_item_to_list "$i" "$new_list"`
	done
	echo "$new_list"
}

#Tree.txt Generation ####################################
gen_dm_tree(){
	file=$1
	dyn_obj=$2

	#Get line number of lines containing Object or Param
	leaf_obj_line=`get_leaf_obj_line_number "$file"`

	for line_number in $leaf_obj_line; do
		#Get table name
		table_name=`sed -n $line_number'p' $file | cut -d' ' -f2 | tr -d []`
		str=`sed -n $line_number'p' $file | grep "DMOBJ"`
		parameters_list=""
		objects_list=""
		o_found="0"
		p_found="0"
		
		######## Before looking for childs Look to father
		for obj in $obj_look_obj_child_list; do
			childs_obj=`echo $obj | awk -F ":" '{print $2}'`
			if [ "$childs_obj" == "$table_name" ]; then  #I found mum
				father_name=`echo $obj | awk -F ":" '{print $1}'`
				o_found="1"
				break
			fi
		done

		for param in $obj_look_param_child_list; do
			childs_params=`echo $param | awk -F ":" '{print $2}'`
			if [ "$childs_params" == "$table_name" ]; then  #I found mum
				father_name=`echo $param | awk -F ":" '{print $1}'`
				p_found="1"
				break
			fi
		done
	
		######## Create Childs list
		while IFS=, read -r f1 f2 f3 f4 f5 f6 f7 f8 f9 f10 f11; do
			name=`echo ${f1/CUSTOM_PREFIX/$CUSTOM_PREFIX} | sed 's/{//' | sed 's/"//g'`
			type=${f3// }
			multiinstance=${f5// }

			if [ "$multiinstance" != "NULL" ]; then
				instance="true"
			else
				instance="false"
			fi

			if [ "$dyn_obj" -eq "1" ];then
				echo "object,$instance,root,Device,$name," >> $TREE_TXT
			fi

			if [ "$o_found" == "1" ]; then
				name=`set_obj_object_child "$father_name" "$name"`
				oname=`set_obj_object_line $instance "$name"`
				echo "$oname," >> $TREE_TXT
			fi

			if [ "$p_found" == "1" ]; then
				name=`set_obj_param_child "$father_name" "$name"`
				otype=`get_param_type $type`
				pname=`set_obj_param_line "$otype" "$name"`
				echo $pname >> $TREE_TXT
			fi

			if [ -n "$str" ]; then
				child_objects=${f7// }
				child_parameters=${f8// }
				obj_name=${name}

				#Add the actual object to the list of objects looking for their children objects ########
				if [ "$child_objects" != "NULL" ]; then
					if [ "$dyn_obj" -eq "1" ];then
						new_item="Device,"${obj_name}":"${child_objects}
					else
						new_item=${obj_name}":"${child_objects}
					fi
					obj_look_obj_child_list=`add_item_to_list "$new_item" "$obj_look_obj_child_list"`
				fi

				#Add the actual object to the list of objects looking for their children parameters #######
				if [ "$child_parameters" != "NULL" ]; then
					if [ "$dyn_obj" -eq "1" ];then
						new_item="Device,"${obj_name}":"${child_parameters}
					else
						new_item=${obj_name}":"${child_parameters}
					fi
					obj_look_param_child_list=`add_item_to_list "$new_item" "$obj_look_param_child_list"`
				fi
			fi
			dyn_obj=0
		done <<<"`sed -n $line_number',/{0}/p' $file | cut -d \" \" -f 1-4,6- | sed '/#ifdef GENERIC_OPENWRT/,/#else/d' | sed -e '/{0}/d' | sed -e '/^{/!d'`"
		
		######### Remove object from list of object looking there childs
		for obj in $obj_look_obj_child_list; do
			childs_obj=`echo $obj | awk -F ":" '{print $2}'`
			if [ "$childs_obj" == "$table_name" ]; then  #I found mum
				obj_look_obj_child_list=`remove_item_from_list "$obj" "$obj_look_obj_child_list"`
				break
			fi
		done
		
		######### Remove object from list of object looking there childs
		for param in $obj_look_param_child_list; do
			childs_params=`echo $param | awk -F ":" '{print $2}'`
			if [ "$childs_params" == "$table_name" ]; then  #I found mum
				obj_look_param_child_list=`remove_item_from_list "$param" "$obj_look_param_child_list"`
				break
			fi
		done
	done
}
#XML Generation Functions ####################################
xml_open_tag_object() {
	local objn="$1"
	local isarray="$2"
	local level="$3"
	local h_child="$4"
	local sp1=0 sp2=0
	let sp1=8+4*$level
	let sp2=$sp1+4
	printf "%${sp1}s"; echo "<parameter>"
	printf "%${sp2}s"; echo "<parameterName>$objn</parameterName>"
	printf "%${sp2}s"; echo "<parameterType>object</parameterType>"
	printf "%${sp2}s"; echo "<array>$isarray</array>"
	if [ -n "$h_child" -a "$h_child" != "0" ]; then
		printf "%${sp2}s"; echo "<parameters>"
	fi
}

xml_close_tag_object() {
	local level="$1"
	local h_child="$2"
	local sp1=0 sp2=0
	let sp1=8+4*$level
	let sp2=$sp1+4
	if [ -n "$h_child" -a "$h_child" != "0" ]; then
		printf "%${sp2}s"; echo "</parameters>"
	fi
	printf "%${sp1}s"; echo "</parameter>"
}

xml_add_parameter() {
	local paramn="$1"
	local type="$2"
	local level="$3"
	local sp1=0 sp2=0
	let sp1=8+4*$level
	let sp2=$sp1+4

	printf "%${sp1}s"; echo "<parameter>"
	printf "%${sp2}s"; echo "<parameterName>$paramn</parameterName>"
	printf "%${sp2}s"; echo "<parameterType>$type</parameterType>"
	printf "%${sp1}s"; echo "</parameter>"
}


xml_write_line() {
	local level="$1"
	local parent="$2"
	local path="$3"
	local line=""
	
	local LINES=`grep "$path[^,]\+$\|$path[^,]\+,$" $OUT_STREAM`

	for line in $LINES; do
		local p=`echo "$line" | cut -d, -f$((level+2))`
		[ "$p" != "$parent" ] && continue
		local param=`echo "$line" | cut -d, -f$((level+3))`
		[ "$param" = "" ] && continue
		local node=`echo "$line" | cut -d, -f1`
		if [ "$node" = "object" ]; then
			local isarray=`echo "$line" | cut -d, -f2`
			let cnt_obj++
			local has_child=`grep "$path$param,[a-zA-Z0-9_,]\+$" $OUT_STREAM |wc -l`;
			xml_open_tag_object "$param" "$isarray" "$level" "$has_child"
			xml_write_line "$((level+1))" "$param" "$path$param,"
			xml_close_tag_object "$level" "$has_child"
		elif [ "$node" = "parameter" ]; then
			local type=`echo "$line" | cut -d, -f2`
			let cnt_param++
			xml_add_parameter "$param" "$type" "$level"
		fi
	done
}

gen_data_model_xml_file() {
echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
echo "<deviceType xmlns=\"urn:dslforum-org:hdm-0-0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"urn:dslforum-org:hdm-0-0 deviceType.xsd\">"
echo "    <protocol>$DEVICE_PROTOCOL</protocol>"
echo "    <manufacturer>iopsys</manufacturer>"
echo "    <manufacturerOUI>002207</manufacturerOUI>"
echo "    <productClass>$PRODUCT_CLASS</productClass>"
echo "    <modelName>$MODEL_NAME</modelName>" 
echo "    <softwareVersion>$SOFTWARE_VERSION</softwareVersion>"
echo "    <dataModel>"
echo "        <attributes>"
echo "            <attribute>"
echo "                <attributeName>notification</attributeName>"
echo "                <attributeType>int</attributeType>"
echo "                <minValue>0</minValue>"
echo "                <maxValue>2</maxValue>"
echo "            </attribute>"
echo "            <attribute>"
echo "                <attributeName>accessList</attributeName>"
echo "                <attributeType>string</attributeType>"
echo "                <array>true</array>"
echo "                <attributeLength>64</attributeLength>"
echo "            </attribute>"
echo "            <attribute>"
echo "                <attributeName>visibility</attributeName>"
echo "                <attributeType>string</attributeType>"
echo "                <array>true</array>"
echo "                <attributeLength>64</attributeLength>"
echo "            </attribute>"
echo "        </attributes>"
echo "        <parameters>"
xml_write_line "1" "root" "root,"
echo "        </parameters>"
echo "    </dataModel>"
echo "</deviceType>"
}

display_usage() {
	echo "Usage: $0 [-r|--remote-dm urls] [-p|--product-class] [-d|--device-protocol] [-m|--model-name] [-s|--software-version] [-h|--help]"
	echo "Options: "
	echo "  -r, --remote-dm           generate data model tree using dynamic OBJ/PARAM under these repositories"
	echo "  -p, --product-class       generate data model tree using this product class, default:DG400PRIME"
	echo "  -d, --device-protocol     generate data model tree using this device protocol, default:DEVICE_PROTOCOL_DSLFTR069v1"
	echo "  -m, --model-name          generate data model tree using this model name, default:DG400PRIME-A"
	echo "  -s, --software-version    generate data model tree using this software version, default:1.2.3.4"
	echo "  -h, --help                This help text"
	echo ""
	echo "Examples: "
	echo " - sh $0"
	echo " - sh $0 --remote-dm https://dev.iopsys.eu/feed/iopsys.git^devel,https://dev.iopsys.eu/iopsys/mydatamodel.git^5c8e7cb740dc5e425adf53ea574fb529d2823f88"
	echo " - sh $0 -p DG300 -s BETA5.3.4 -r https://dev.iopsys.eu/feed/iopsys.git^6.0.0ALPHA1"
	echo ""
}

############################################### MAIN ######################################################

# set initial values
CURRENT_PATH=`pwd`
OUT_STREAM=".tmp.txt"
ROOT_FILE="device.c"
TREE_TXT=$CURRENT_PATH"/"$OUT_STREAM
DM_PATH="$(pwd)/../dmtree"
PRODUCT_CLASS="DG400PRIME"
DEVICE_PROTOCOL="DEVICE_PROTOCOL_DSLFTR069v1"
MODEL_NAME="DG400PRIME-A"
SOFTWARE_VERSION="1.2.3.4"
cnt_obj=0
cnt_param=0
DM_TR181="tr181"
DM_TR104="tr104"
DM_TR143="tr143"
DM_TR157="tr157"
SCRIPTS_PATH_TR181=${DM_PATH}/${DM_TR181}
SCRIPTS_PATH_TR104=${DM_PATH}/${DM_TR104}
SCRIPTS_PATH_TR143=${DM_PATH}/${DM_TR143}
SCRIPTS_PATH_TR157=${DM_PATH}/${DM_TR157}
DIR_LIST="$SCRIPTS_PATH_TR181 $SCRIPTS_PATH_TR104 $SCRIPTS_PATH_TR143 $SCRIPTS_PATH_TR157"
XML_OUT_STREAM_BBF="iopsys.xml"
ROOT_PATH="Device"
CUSTOM_PREFIX="X_IOPSYS_EU_"

# read the options
OPTS=$(getopt --options r:p:d:m:s:h --long remote-dm:,product-class:,device-protocol:,model-name:,software-version:,help --name "$0" -- "$@")

if [ $? != 0 ]; then echo "Failed to parse options...exiting." >&2 ; exit 1 ; fi

eval set -- "$OPTS"

# extract options and their arguments into variables.
while true ; do
	case "$1" in
		-r | --remote-dm )
			REMOTEDM="$2"
			shift 2
			;;
		-p | --product-class )
			PRODUCT_CLASS="$2"
			shift 2
			;;
		-d | --device-protocol )
			DEVICE_PROTOCOL="$2"
			shift 2
			;;
		-m | --model-name )
			MODEL_NAME="$2"
			shift 2
			;;
		-s | --software-version )
			SOFTWARE_VERSION="$2"
			shift 2
			;;
		-h | --help )
			display_usage
			exit 0
			;;
		-- )
			shift
			break
			;;
		*)
			echo "Internal error!"
			exit 1
			;;
	esac
done

# download remote data models if exists
if [ -n "$REMOTEDM" ]; then
	echo "Start downloading remote data models..."
	echo "Download in progress........"
	i=0
	for dm_url in $(echo $REMOTEDM | tr "," "\n"); do
		URL="${dm_url%^*}"
		BRANCH="${dm_url#*^}"
		git clone $URL ".repo$i" > /dev/null 2>&1
		git -C ".repo$i" checkout $BRANCH > /dev/null 2>&1
		let "i++"
	done
fi

############## GEN BBF Data Models TREE ##############
echo "Start Generation of BBF Data Models..."
echo "Please wait..."

rm -rf $OUT_STREAM
rm -rf $XML_OUT_STREAM_BBF

echo "object,false,root,$ROOT_PATH," > $OUT_STREAM

cd "$SCRIPTS_PATH_TR181"
gen_dm_tree $ROOT_FILE "0"
for dir in $DIR_LIST; do
	cd $dir
	files=`ls *.c |grep -v $ROOT_FILE`
	for file in $files; do
		gen_dm_tree "$file" "0"
	done
done

cd $CURRENT_PATH
if [ -n "$REMOTEDM" ]; then
	i=0
	for dm_url in $(echo $REMOTEDM | tr "," "\n"); do
		files=`find .repo$i -name datamodel.c`
		for file in $files; do
			gen_dm_tree "$file" "1"
		done
		let "i++"
	done
fi

sort -k 4 $OUT_STREAM > tmp2.txt
cat tmp2.txt | tr -d "[:blank:]" > $OUT_STREAM
rm -rf tmp2.txt
gen_data_model_xml_file > $XML_OUT_STREAM_BBF

cnt_obj=`grep -c "object," $OUT_STREAM`
cnt_param=`grep -c "parameter," $OUT_STREAM`

echo "Number of BBF Data Models objects is $cnt_obj"
echo "Number of BBF Data Models parameters is $cnt_param"
echo "End of BBF Data Models Generation"

if [ -n "$REMOTEDM" ]; then
	i=0
	for dm_url in $(echo $REMOTEDM | tr "," "\n"); do
		rm -rf ".repo$i"
		let "i++"
	done
fi

rm -rf $OUT_STREAM
