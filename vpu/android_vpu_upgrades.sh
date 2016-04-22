#!/bin/bash -x

set +x

re_checkout_all=0

# ================  default value for input =========================
TAG_FROM="imx-android-r9.1-rc3"
MYANDROID_DIR="../../../"
COMMIT_FILE=""
LIB_TO="up2date"
FIRMWARE_TO="up2date"

# ==================== global variables =============================
current_dir=`pwd`
target_dir=""   # place result tar.gz file here
repo_name=""
root=""    # another name for MYANDROID_DIR
# ==================== function definitions =========================


checkResult()
{
    if [ $? != 0 ]; then
        echo Fail!!!
        exit 0
    fi
}

log()
{
    printf "\n$1\n\n"
}

cleanUpGit()
{
    # clean up modified files
    if [ "`git status | grep modified`" != "" ]; then
        git checkout `git status | grep modified | awk '{printf("%s\n",$3);}' `
    fi

}

# get comments of commit and output to $1
GetLastCommit()
{
    file_name="-- $2"

    first_commit=0
    git log --stat $file_name | while read -r line
    do
        if [ "${line:0:6}" = "commit" ]; then
            if [ $first_commit -eq 1 ]; then
                 break
            else
                 first_commit=1
            fi

        fi
        echo "        $line" >> $1
    done
}


showHelp()
{
    echo "Usage : vpu_upgrade.sh parameters"
    echo "parameters:"
    echo "          -from [tag_from] "
    echo "          -lib_to [lib_to]   - optional. target of external/linux-lib. default: up2date"
    echo "          -dir [path of myAndroid]"
    echo "          -patch [commit_file]       - optional. "
    echo "          -firmware_to [firmware_to] - optional. default: up2date. commit or tag for external/linux-firmware-imx/firmware/vpu/"
    echo "                                                 none: do not include firmware in package"
    echo ""
    echo "Example:  ./vpu_upgrade.sh -from imx-android-r9.2-rc3 -lib_to imx-android-r9.4-rc3 -dir ../../../"
    echo ""
    echo "Notes:"
    echo "          [lib_to] can be \"up2date\", tag number, or commit number"
    echo "          [commit_file] contains the commit numbers of lib that need to build into this package"
    echo "                        commit numbers shall be in sequence from old to new"

}


# =================== get parameters ================================
set +x

if [ "$1" = "-h" ] || [ "$1" = "--help" ] ; then
    showHelp
    exit 0
fi

get_from=0
get_lib_to=0
get_dir=0
get_patch=0
get_firmware=0

clearFlags()
{
    get_from=0
    get_lib_to=0
    get_dir=0
    get_patch=0
    get_firmware=0
}

for arg in $@
do
    if [ "$arg" = "-from" ]; then
        clearFlags
        get_from=1
        continue
    fi
    if [ "$arg" = "-lib_to" ]; then
        clearFlags
        get_lib_to=1
        continue
    fi
    if [ "$arg" = "-dir" ]; then
        clearFlags
        get_dir=1
        continue
    fi
    if [ "$arg" = "-patch" ]; then
        clearFlags
        get_patch=1
        continue
    fi
    if [ "$arg" = "-firmware_to" ]; then
        clearFlags
        get_firmware=1
        continue
    fi

    if [ $get_from -eq 1 ]; then
        TAG_FROM=$arg
        clearFlags
        continue
    fi

    if [ $get_lib_to -eq 1 ]; then
        LIB_TO=$arg
        clearFlags
        continue
    fi

    if [ $get_dir -eq 1 ]; then
        MYANDROID_DIR=$arg
        clearFlags
        continue
    fi

    if [ $get_patch -eq 1 ]; then
        COMMIT_FILE=$arg
        clearFlags
        continue
    fi
    if [ $get_firmware -eq 1 ]; then
        FIRMWARE_TO=$arg
        clearFlags
        continue
    fi
done

repo_name="repomad/maddev_gingerbread"

echo $TAG_FROM | grep "r9."
if [ $? = 0 ]; then
    repo_name="repomad/maddev_froyo"
fi

echo $TAG_FROM | grep "r9.2."
if [ $? = 0 ]; then
    repo_name="repomad/maddev-imx-android-r9.2-postrelease"
fi

echo $TAG_FROM | grep "r9.4."
if [ $? = 0 ]; then
    repo_name="repomad/maddev-imx-android-r9.4-postrelease"
fi

echo repo_name=$repo_name

if [ "$COMMIT_FILE" != "" ]; then
    if [ ! -f $COMMIT_FILE ]; then
        echo $COMMIT_FILE does not exist!!!
        exit 1
    fi
    COMMIT_FILE=$current_dir/$COMMIT_FILE
fi

if [ ! -d $MYANDROID_DIR ]; then
    echo $MYANDROID_DIR does not exist!!!
    exit 1
fi

cd $MYANDROID_DIR
root=$(pwd)
#echo root=$root

echo check input correctness!!!
echo ==================================================
echo "tag_from      =>  $TAG_FROM"
echo "lib_to    =>  $LIB_TO"
echo "myAndroid_dir =>  $root"
echo "commit_file   =>  $COMMIT_FILE"
echo "firmware_to   =>  $FIRMWARE_TO"
echo ==================================================

sleep 5

set +x
log " =============== checkout for $TAG_FROM ========================"
set -x

cd $root/external/linux-lib
cleanUpGit

cd $root
if [ -f repo ]; then
	repo_cmd="./repo"
else
	which repo
	if [ $? -eq 0 ]; then
	    repo_cmd="repo"
	else
	    echo "No repo command found!!!"
	    exit 1
	fi
fi

cd $root/external/linux-lib
git tag | grep "$TAG_FROM"
#if [ $? -ne 0 ]; then
	#cd $root
	#./repo forall -c git fetch repomad --tags > log 2>&1;       # may fail
#fi

if [ "$re_checkout_all" -eq 1 ]; then
	cd $root
	$repo_cmd forall -c git checkout $TAG_FROM > log 2>&1;         # may fail
fi

cd $root/external/linux-lib
git checkout -f $TAG_FROM > log 2>&1 ;                                   checkResult

current_date=`date +%Y%m%d_%H%M`

final_name=${TAG_FROM}_${current_date}

cd $current_dir
target_dir=$current_dir/Upgrade_vpu_${final_name}

rm -rf $target_dir
mkdir $target_dir

cd $root

set +x
log "================ make patch for external/linux-lib ==========================="
set -x

if [ "$TAG_FROM" = "$LIB_TO" ]; then
        make_vpu_lib_patch=false
else
	make_vpu_lib_patch=true
fi

if [ "$make_vpu_lib_patch" = "true" ];then

	echo search date of last commit in git log of $TAG_FROM

	cd $root/external/linux-lib ;                                             checkResult

	git log --stat > git_log

	# // get date of last commit in TAG_FROM //

	date_from=0

	set +x

	search_end=false
	while [ "$search_end" = "false" ];
	do
	    read -r line
	    if [[ "${line:0:6}" = "commit" ]]; then
		    read -r line
		    read -r line
		    if [[ ${line:0:4} = "Date" ]]; then
			date_from=${line#*"Date: "}
			onecommit_end=""
			while [ "$onecommit_end" = "" ];
			do
				read -r line
				findstring_vpu=`echo $line | egrep -I 'vpu'`
				if [ "$findstring_vpu" != "" ]; then
					echo date_from is $date_from
					search_end=true
					break
				fi
				onecommit_end=`echo $line | egrep -I 'insertions'`
			done
		    fi
            fi
	done < git_log

	set -x

	if [[ "$date_from" = 0 ]]; then
	    echo read date_from fail in $TAG_FROM external/linux-lib!!!
	    exit 0
	fi

	rm -f git_log


	if [ "$LIB_TO" != "up2date" ]; then
	    git checkout -f $LIB_TO > log 2>&1;   # may fail
	else
	    git remote update;                            checkResult
	    git checkout -f fsl-linux-sdk/master;         checkResult
	fi


	git log --stat > git_log

	commit_from=0

	set +x

	while read -r line
	do
	    # // search last commit of $tag_to in git log //
	    if [[ "${line:0:6}" = "commit" ]]; then
		commit_to=${line#*"commit "}
		read -r line
		read -r line
		if [[ "${line:0:4}" = "Date" ]]; then
		    date_to=${line#*"Date: "}
		    echo date_to is $date_to,commit_to is $commit_to
		    break
		else
		    echo read date in git log of $tag_to in external/linux-lib fail!!!
		    exit 0
		fi
	    else
		echo read git log of $tag_to in external/linux-lib fail!!!
		exit 0
	    fi
	done < git_log

	while read -r line
	do
	    # // search last commit of $TAG_FROM in git log of $tag_to //
	    if [[ "${line:0:6}" = "commit" ]]; then
		commit_temp=${line#*"commit "}
		read -r line
		read -r line
		if [[ "${line:0:4}" = "Date" ]]; then
		    date_temp=${line#*"Date: "}
		    if [[ "$date_temp" = "$date_from" ]]; then
			commit_from=$commit_temp
			echo commit_from=$commit_from
			break
		    fi
		fi

	    fi
	done < git_log

	set -x

	if [[ $commit_from = 0 ]]; then
	    echo search commit_from of date: $date_from in git log fail!!!
	    exit 0
	fi

        # // generate patch files and output to all.patch //

	rm -f git_log
	rm -f *.patch

        if [[ $commit_from = $commit_to ]];then
            make_vpu_lib_patch=false
        fi

fi

if [ "$make_vpu_lib_patch" = "true" ];then


	git format-patch $commit_from..$commit_to ;                                  checkResult

        # // output valid patch name into patch_files //
	egrep -l 'vpu' *.patch > patch_files            # $? is 1 when not found

	rm -f all.patch
	touch all.patch

	if [ -s patch_files ]; then
	    while read -r line
	    do
		cat $line >> all.patch
	    done < patch_files

            # // only record commit log when we have patchs //
            rm -f commit_log
            GetLastCommit commit_log
	fi

	#rm -f patch_files
	#rm -f 0*.patch

fi

set +x
log " =================== check to TAG_FROM ========================="
set -x

if [ "$make_vpu_lib_patch" = "true" ];then
	cd $root/external/linux-lib
	git checkout $TAG_FROM > log 2>&1
fi

set +x
log " ========== apply patch to TAG_FROM of  external/linux-lib =============="
set -x

if [ "$make_vpu_lib_patch" = "true" ];then

	cd $root/external/linux-lib
	mv all.patch vpu_lib.patch  ;                                      checkResult

	cleanUpGit

	if [ -s vpu_lib.patch ]; then
	    git apply vpu_lib.patch;                                               # may fail
	fi

fi

patch_count=0

set +x
log "===================== make firmware package ===================="
set -x

if [ "$FIRMWARE_TO" != "none" ]; then

	cd ${root}/external/linux-firmware-imx;                                 checkResult
	cleanUpGit
	git remote update

	if [ "$FIRMWARE_TO" = "up2date" ]; then
	    git checkout fsl-linux-sdk/master;                                       checkResult
	else
	    git checkout $FIRMWARE_TO;                                                  checkResult
	fi

	cd $root
	firmware_list="external/linux-firmware-imx/firmware/vpu/vpu_fw_imx51.bin
		       external/linux-firmware-imx/firmware/vpu/vpu_fw_imx53.bin
		       external/linux-firmware-imx/firmware/vpu/Android.mk"

	tar czvf firmware.tar.gz $firmware_list;                                         checkResult
fi

set +x
log "====================== collect packages ========================"
set -x


if [ -s $root/external/linux-lib/vpu_lib.patch ]; then
    mv $root/external/linux-lib/vpu_lib.patch $target_dir;                  checkResult
fi

if [ "$FIRMWARE_TO" != "none" ]; then
	mv $root/firmware.tar.gz $target_dir ;               checkResult
fi

cd $target_dir

if [ "$COMMIT_FILE" != "" ]; then
    cp $COMMIT_FILE ./commit_file ;                                              checkResult
fi

if [ -f README.TXT ]; then
    rm README.txt
fi

readme_content="                         \n
1.                                       \n
If vpu_lib.patch exists          \n
$ cd \${YOUR_ANDROID_SRC_DIR}/external/linux-lib \n
$ git apply vpu_lib.patch        \n
                                         \n
2.                                       \n
If firmware.tar.gz exists          \n
$ cd \${YOUR_ANDROID_SRC_DIR}            \n
$ tar -xzvf firmware.tar.gz              \n
"

echo -e $readme_content > README.txt

if [ "$FIRMWARE_TO" != "none" ]; then
	file_list="$file_list firmware.tar.gz"
fi

if [ "$make_vpu_lib_patch" = "true" ] && [ -f vpu_lib.patch ] ; then
    file_list="$file_list vpu_lib.patch"
fi

tar czvf Upgrade_vpu_${final_name}.tar.gz $file_list;                               checkResult
rm -f $file_list

# ================= generate log.txt ================================

if [ -f log.txt ]; then
	rm -f log.txt
fi

echo -e "tag_from = $TAG_FROM \n"                               >> log.txt
echo "lib_to = $LIB_TO"                                 >> log.txt
if [ -f ${root}/external/linux-lib/commit_log ]; then
    echo "    last commit of external/linux-lib:"                  >> log.txt
    cat ${root}/external/linux-lib/commit_log                      >> log.txt
    rm -f ${root}/external/linux-lib/commit_log
fi

echo "firmware_to = $FIRMWARE_TO"                               >> log.txt
echo "    last commit of external/linux-firmware-imx:"          >> log.txt
cd ${root}/external/linux-firmware-imx;                         checkResult
GetLastCommit ${target_dir}/log.txt
cd $target_dir

set +x
echo ""
echo "upgrade packaging finished in `basename $target_dir`"
echo ""

exit 0

