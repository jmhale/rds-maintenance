#!/usr/bin/env python3
"""
RDS Functions
"""

import sys
from datetime import datetime, timedelta
from exclusions import EXCLUDED_INSTANCES
import boto3
import botocore

## Session/client setup operations
def get_session(access_key_id, secret_access_key):
    " Establishes a session with AWS "
    return boto3.session.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key
    )

## EC2 operations
def get_vpc_ids(client):
    " Returns a list of VPC IDs in the account "
    vpc_ids = []
    vpcs = client.describe_vpcs()['Vpcs']
    for vpc in vpcs:
        vpc_ids.append(vpc['VpcId'])
    return vpc_ids

def get_isolated_sgs(client):
    " Returns a dict of rds-isolate SG IDs for each VPC in account. "
    vpc_ids = get_vpc_ids(client)
    isolated_sgs = {}
    for vpc in vpc_ids:
        sec_groups = client.describe_security_groups(
            Filters=[
                {
                    "Name": "vpc-id",
                    "Values": [vpc]
                },
                {
                    "Name": "group-name",
                    "Values": ["rds-isolate"]
                }
            ]
        )['SecurityGroups']
        try:
            isolated_sgs[vpc] = sec_groups[0]['GroupId']
        except IndexError:
            print("No rds-isolate group found for VPC: {}".format(vpc))
    return isolated_sgs

## Cloudwatch operations
def get_connections_statistics(client, rds_instances):
    " Returns a dict of all instances and their avg DB conns over all datapoints "
    rds_stats = {}
    for rds_instance in rds_instances:
        stats = client.get_metric_statistics(
            Namespace="AWS/RDS",
            MetricName="DatabaseConnections",
            Statistics=['Average'],
            Period=57600,
            StartTime=(datetime.today() - timedelta(days=3)),
            EndTime=datetime.today(),
            Dimensions=[
                {
                    'Name': 'DBInstanceIdentifier',
                    'Value': rds_instance['DBInstanceIdentifier']
                }
            ]
        )['Datapoints']
        datapoints = []
        for stat in stats:
            datapoints.append(stat['Average'])
        if len(datapoints) > 0:
            dp_conns = sum(datapoints)/float(len(datapoints))
            rds_stats[rds_instance['DBInstanceIdentifier']] = dp_conns
        else:
            print("Instance: %s has no datapoints." % rds_instance['DBInstanceIdentifier'])

    return rds_stats

## RDS operations
def get_rds_instances(client, vpc_id=None):
    " Gets all RDS instances, per VPC, if specified. "

    rds_instances = []
    resp = client.describe_db_instances()
    while 'Marker' in resp:
        rds_instances.extend(resp['DBInstances'])
        resp = client.describe_db_instances(Marker=resp['Marker'])
    rds_instances.extend(resp['DBInstances'])
    if not vpc_id:
        return rds_instances
    else:
        return [r for r in rds_instances if r['DBSubnetGroup']['VpcId'] == vpc_id]

def set_no_multiaz(client, rds_instance):
    " Takes a rds instance obj and turns off MultiAZ "
    try:
        client.modify_db_instance(
            DBInstanceIdentifier=rds_instance['DBInstanceIdentifier'],
            MultiAZ=False,
            ApplyImmediately=True
        )
    except botocore.exceptions.ClientError:
        print("Error setting no-multiaz on instance %s" % rds_instance['DBInstanceIdentifier'])

def set_security_group(client, rds_instance, sg_id):
    " Sets the rds_instance Security Group to sg_id "
    try:
        client.modify_db_instance(
            DBInstanceIdentifier=rds_instance['DBInstanceIdentifier'],
            VpcSecurityGroupIds=[sg_id]
        )
    except botocore.exceptions.ClientError:
        print("Error setting SG on instance %s" % rds_instance['DBInstanceIdentifier'])

def set_instance_size(client, rds_instance, size=None):
    " Sets instance to the smallest available size "
    if not size:
        available_sizes = client.describe_orderable_db_instance_options(
            Engine=rds_instance['Engine']
        )['OrderableDBInstanceOptions']
        size = available_sizes[0]['DBInstanceClass']
    try:
        client.modify_db_instance(
            DBInstanceIdentifier=rds_instance['DBInstanceIdentifier'],
            DBInstanceClass=size,
            ApplyImmediately=True
        )
    except botocore.exceptions.ClientError:
        print("Error setting size on instance %s" % rds_instance['DBInstanceIdentifier'])

def get_instances_with_sg(client, sg_id, vpc_id=None):
    """ Gets all RDS instances that are using the sg_id """
    rds_instances = get_rds_instances(client, vpc_id)

    instances_with_sg = []
    for instance in rds_instances:
        security_groups = instance['VpcSecurityGroups']
        for security_group in security_groups:
            if security_group['VpcSecurityGroupId'] == sg_id:
                instances_with_sg.append(instance)

    return instances_with_sg

def take_snapshot(client, rds_instance):
    """ Takes a snapshot of an RDS instance """

    resp = client.create_db_snapshot(
        DBSnapshotIdentifier='%s-final-snapshot' % rds_instance['DBInstanceIdentifier'],
        DBInstanceIdentifier=rds_instance['DBInstanceIdentifier'],
    )
    print("Created final snapshot for %s, %s"
          % (rds_instance['DBInstanceIdentifier'], resp['DBSnapshot']['DBSnapshotIdentifier']))

## CloudFormation operations
def get_cfn_stacks():
    """ Returns all CFN stacks """
    #TODO
    pass

def destroy_cfn_stack():
    """ Destroys a Cloudformation stack """
    #TODO
    pass

##
def get_old_instances(ec2, rds, debug=True):
    """ Gets RDS instances slated for decomm """
    isolated_sgs = get_isolated_sgs(ec2)
    old_instances = []
    for group in isolated_sgs.values():
        isolated_instances = get_instances_with_sg(rds, group)
        for instance in isolated_instances:
            old_instances.append(instance)

    if debug:
        for instance in old_instances:
            print(instance['DBInstanceIdentifier'])
        print("%s instances found." % len(old_instances))
    return old_instances

def snapshot_old_rds_instances(rds, old_instances, dry_run=True):
    """ Performs a final snapshot on old RDS instances. """
    for instance in old_instances:
        if not dry_run:
            take_snapshot(rds, instance)
        else:
            print("DRYRUN: Would have taken a snapshot of %s" % instance['DBInstanceIdentifier'])

def prep_rds_instances_for_decomm(ec2, rds, cloudwatch, dry_run=True, debug=True):
    """
    Finds RDS instances with low connection counts and
    applies an isolated SG, sizes it down and sets to single AZ
    """

    isolated_sgs = get_isolated_sgs(ec2)
    all_rds_instances = get_rds_instances(rds)
    all_rds_stats = get_connections_statistics(cloudwatch, all_rds_instances)
    if debug:
        print("DEBUG: Number of RDS instances found: %s" % len(all_rds_instances))
        print("DEBUG: Isolated SGs {}".format(isolated_sgs))
        print("DEBUG: All RDS Instances: ")
        for instance in all_rds_instances:
            print(instance['DBInstanceIdentifier'])
    abandoned_instances = []
    if len(EXCLUDED_INSTANCES) > 0:
        print("\nThe following instances meet low connections criteria, but have been excluded.")
    for key in all_rds_stats:
        if all_rds_stats[key] == 0 and key not in EXCLUDED_INSTANCES:
            abandoned_instances.append(key)
        elif all_rds_stats[key] == 0 and key in EXCLUDED_INSTANCES:
            print(key)
        if debug:
            print("DEBUG: Instance: %s. Connections: %s" % (key, all_rds_stats[key]))
    if len(abandoned_instances) > 0:
        print("\nThe following instances appear to be abandoned. Please investigate.")
        for instance in abandoned_instances:
            print(instance)
    else:
        print("\nNo instances appear to be abandoned.")
        sys.exit(0)
    print("\nTaking action on the following instances: ")
    for rds_instance in all_rds_instances:
        if rds_instance['DBInstanceIdentifier'] in abandoned_instances:
            if dry_run:
                print("DRYRUN: %s would have been isolated and downsized."
                      % rds_instance['DBInstanceIdentifier'])
            else:
                print("Isolating and downsizing instance: %s"
                      % rds_instance['DBInstanceIdentifier'])
                set_security_group(rds,
                                   rds_instance,
                                   isolated_sgs[rds_instance['DBSubnetGroup']['VpcId']])

                set_instance_size(rds,
                                  rds_instance,
                                  'db.t2.micro')

                set_no_multiaz(rds, rds_instance)

def main():
    """ main execution """
    dry_run = True
    debug = True

    session = get_session('', '')
    ec2 = session.client('ec2')
    rds = session.client('rds')
    cdw = session.client('cloudwatch')
    cfn = session.client('cloudformation')

    # prep_rds_instances_for_decomm(ec2, rds, cfn, dry_run, debug)
    old_instances = get_old_instances(ec2, rds, debug)
    snapshot_old_rds_instances(rds, old_instances, dry_run)

main()
