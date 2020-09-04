import pandas as pd
from sklearn.preprocessing import LabelEncoder, KBinsDiscretizer


def train_test(train, test):

    # Add u2r attack
    list_add = []
    list_add = pd.DataFrame(list_add)

    for count in range(len(train)):

        if train['Class'][count] == 'u2r.':
            list_add = pd.concat([train.iloc[[count]], list_add])

        if train['Class'][count] == 'buffer_overflow.':
            list_add = pd.concat([train.iloc[[count]], list_add])

        if train['Class'][count] == 'loadmodule.':
            list_add = pd.concat([train.iloc[[count]], list_add])

        if train['Class'][count] == 'perl.':
            list_add = pd.concat([train.iloc[[count]], list_add])

        if train['Class'][count] == 'rootkit.':
            list_add = pd.concat([train.iloc[[count]], list_add])

    for a in range(20):
        train = pd.concat([list_add, train])

    # Merge train and test
    frames = [train, test]
    dataSet = pd.concat(frames, ignore_index=True)

    # Split x and y
    dataSet_x = pd.DataFrame(dataSet).drop(columns=['Class'])
    dataSet_y = dataSet['Class']

    # Encoding categorical features
    le = LabelEncoder()
    dataSet_x['protocol_type'] = le.fit_transform(dataSet_x['protocol_type'])
    dataSet_x['service'] = le.fit_transform(dataSet_x['service'])
    dataSet_x['flag'] = le.fit_transform(dataSet_x['flag'])

    dataSet_x = pd.DataFrame(dataSet_x,  columns=['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'])

    continuous_features = ['duration', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
                           'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                           'num_access_files', 'num_outbound_cmds', 'count', 'srv_count', 'serror_rate',
                           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                           'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
                           'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                           'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                           'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']
    other_features = ['protocol_type', 'service', 'flag', 'land',  'logged_in', 'is_host_login', 'is_guest_login']

    # Discretize continuous features
    ct = KBinsDiscretizer(n_bins=22, encode='onehot-dense')
    tmp = ct.fit_transform(dataSet_x[continuous_features])
    tmp = pd.DataFrame(tmp)
    dataSet_x = pd.concat([dataSet_x[other_features], tmp], axis=1)

    x = pd.DataFrame(dataSet_x)
    y = pd.DataFrame(dataSet_y)

    train_y = y.iloc[:495061, :]
    test_y = y.iloc[495061:, :]

    train_x = x.iloc[:495061, :]
    test_x = x.iloc[495061:, :]

    train_y = train_y.values.ravel()
    test_y = test_y.values.ravel()

    return train_x, train_y, test_x, test_y

