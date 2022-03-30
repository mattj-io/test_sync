#!/usr/bin/env python

'''
Check Wordpress for tags
Write tags to Asana
'''

# Instructions
#
# Set your ASANA_ACCESS_TOKEN environment variable
# to a Personal Access Token obtained in your Asana Account Settings
# eg. export ASANA_ACCESS_TOKEN=my_access_token
#

import os
import sys
import logging
from collections import defaultdict
from datetime import datetime
import json
from dateutil import parser
import requests
from bs4 import BeautifulSoup
import asana
import pytz

CONTENT_INDEX_GID = '1200281621424160'
PUBLISH_URL_GID = '1200119254278948'
WORKSPACE_GID = '585985419742490'
HEADERS = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) \
            AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}


def create_lookup_dictionary(client, gid):
    '''
    Create lookup dictionary of tags and gid's
    '''

    result = client.projects.get_project(gid, opt_pretty=True)
    custom_fields = result['custom_field_settings']
    lookup_dict = {}
    for field in custom_fields:
        if "Tag: " in field['custom_field']['name']:
            lookup_dict[(field['custom_field']['name']
                         .replace('Tag: ', '')
                         .lower(),
                         field['custom_field']['gid'])] = {option['name']
                                                           .replace(' ', '-')
                                                           .lower():option['gid']
                                                           for option in
                                                           field['custom_field']['enum_options']}
    return lookup_dict

def filter_list(asana_list, last_run):
    '''
    Filter a set of Asana tasks
    Based on Publish URL being set and modification time before last_run
    ignore anything not under /blog as they have no tags
    Return a dict of Asana gid and publish URL
    '''
    filtered_tasks = {}
    for task in asana_list:
        if parser.isoparse(task['modified_at']) > parser.isoparse(last_run):
            for field in task['custom_fields']:
                if field['name'] == 'Publish URL' \
                and field['text_value'] != None \
                and'/blog/' in field['text_value']:
                    filtered_tasks[task['gid']] = field['text_value']
        else:
            continue
    return filtered_tasks

def get_wp_tags(url):
    '''
    Get WP tags from a URL
    Need to set the User-Agent header to avoid 403 from WP
    '''
    try:
        logging.debug(url)
        res = requests.get(url, headers=HEADERS)
        res.raise_for_status()
        if res.history and '/blog/' not in res.url:
            logging.info("Redirecting %s outside blog", url)
            return False
    except requests.exceptions.HTTPError as err:
        logging.warning(err)
        return False
    
    # Extract the tags and write to a dictionary
    soup = BeautifulSoup(res.text, 'html.parser')
    tags = [x.replace('content-tags-', '')
            for x in soup.article['class'] if 'content-tags' in x]
    wp_tags = {}
    for tag in tags:
        tag_type = tag.split('-', 1)[0]
        tag_value = tag.split('-', 1)[1]
        if tag_type in wp_tags:
            val = wp_tags[tag_type]
            if isinstance(val, list):
                val.append(tag_value)
            else:
                wp_tags[tag_type] = [val, tag_value]
        else:
            wp_tags[tag_type] = [tag_value]
    return wp_tags

def lookup_tags(lookup_table, wp_tags):
    '''
    Lookup tag gids and return JSON object
    '''

    tag_structure = defaultdict(list)
    for lookup_tag, lookup_gid in lookup_table:
        if lookup_tag in wp_tags:
            for wp_tag in wp_tags[lookup_tag]:
                if lookup_tag == 'medium' or lookup_tag == 'contributor':
                    if len(wp_tags[lookup_tag]) > 1:
                        if lookup_tag == 'medium':
                            # The only case this should happen is blog + something else
                            # Note we don't catch an error here if that isn't the case
                            tag_structure[lookup_gid] = lookup_table[lookup_tag, lookup_gid]['blog']
                        elif lookup_tag == 'contributor':
                            # The only case this should happen is devrel + something else
                            # Note we don't catch an error here if that isn't the case
                            tag_structure[lookup_gid] = lookup_table[lookup_tag, lookup_gid]['devrel']
                    else:
                        tag_structure[lookup_gid] = lookup_table[lookup_tag, lookup_gid][wp_tag]
                else:
                    tag_structure[lookup_gid].append(lookup_table[lookup_tag, lookup_gid][wp_tag])
        else:
            # Make sure empty tags in WP are empty in Asana
            if lookup_tag == 'medium' or lookup_tag == 'contributor':
                tag_structure[lookup_gid] = ''
            else:
                tag_structure[lookup_gid] = []
    return json.dumps(tag_structure)

def main():
    '''
    Check WP for tags and write back to Asana
    '''

    # Instructions
    #
    # Set your ASANA_ACCESS_TOKEN environment variable
    # to a Personal Access Token obtained in your Asana Account Settings
    # eg. export ASANA_ACCESS_TOKEN = my_access_token
    #

    if 'ASANA_ACCESS_TOKEN' in os.environ:
        # create a client with a Personal Access Token
        client = asana.Client.access_token(os.environ['ASANA_ACCESS_TOKEN'])
    else:
        print("No access token for Asana")
        sys.exit(1)

    # Add deprecation flag to headers
    client.headers = {'asana-enable': 'new_user_task_lists'}

    # Check for the output log, and extract the datetime for previous run
    # If the log doesn't exist then set last_run to start of epoch

    if os.path.exists('output.log'):
        with open('output.log', 'r') as log_file:
            last_run = log_file.readlines()[-1].split(" - ")[1].rstrip('\r\n')
    else:
        print("No output log")
        last_run = datetime(1970, 1, 1, tzinfo=pytz.utc).isoformat()

    logging.basicConfig(filename='output.log', filemode='w',
                        format='%(levelname)s - %(message)s',
                        level=logging.INFO)
    logging.info('Starting run')
    logging.info(datetime.now(pytz.utc).isoformat())

    # Create a lookup structure from the Content Index board definition

    lookup_table = create_lookup_dictionary(client, CONTENT_INDEX_GID)
    # Get all tasks in the Content Index board
    result = client.tasks.get_tasks_for_project(CONTENT_INDEX_GID,# pylint: disable=E1101
                                                {'opt_fields': 'custom_fields,modified_at'},
                                                opt_pretty=True)

    # Filter on Publish URL, blogs and modification time

    tasks_to_update = filter_list(result, last_run)
    # Iterate tasks and get the webpage from the blog
    for gid, url in tasks_to_update.items():
        wp_tags = get_wp_tags(url)
        if wp_tags:
            # Look up all the tag GID's in the lookup table and construct a JSON object
            json_data = lookup_tags(lookup_table, wp_tags)
            # Write tags back to Asana task
            client.tasks.update_task(gid,# pylint: disable=E1101
                                     {'custom_fields': json_data},
                                     opt_pretty=True)
        else:
            continue
    logging.info('Completed')
    logging.info(datetime.now(pytz.utc).isoformat())

if __name__ == '__main__':
    main()
