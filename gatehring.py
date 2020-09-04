import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, accuracy_score
from sklearn.naive_bayes import GaussianNB
from preprocessing import train_test


train = pd.read_csv("kddcup.data_10_percent.gz", header=None,
                    names=['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
                           'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
                           'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                           'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
                           'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                           'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
                           'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                           'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                           'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'Class'])
test = pd.read_csv("corrected.gz", header=None,
                   names=['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
                          'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
                          'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                          'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
                          'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                          'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
                          'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                          'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                          'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'Class'])


def class_before():
    print('Gathering before classification')

    train['Class'] = train['Class'].replace(['back.', 'land.', 'neptune.', 'pod.', 'smurf.', 'teardrop.'], 'dos.')
    train['Class'] = train['Class'].replace(['buffer_overflow.', 'rootkit.', 'loadmodule.', 'perl.'], 'u2r.')
    train['Class'] = train['Class'].replace(
        ['ftp_write.', 'guess_passwd.', 'imap.', 'multihop.', 'phf.', 'spy.', 'warezclient.', 'warezmaster.'], 'r2l.')
    train['Class'] = train['Class'].replace(['ipsweep.', 'nmap.', 'portsweep.', 'satan.'], 'probe.')

    test['Class'] = test['Class'].replace(
        ['udpstorm.', 'processtable.', 'mailbomb.', 'apache2.', 'back.', 'land.', 'neptune.', 'pod.', 'smurf.',
         'teardrop.'], 'dos.')
    test['Class'] = test['Class'].replace(
        ['httptunnel.', 'xterm.', 'sqlattack.', 'ps.', 'buffer_overflow.', 'rootkit.', 'loadmodule.', 'perl.'], 'u2r.')
    test['Class'] = test['Class'].replace(
        ['xsnoop.', 'xlock.', 'sendmail.', 'named.', 'snmpgetattack.', 'snmpguess.', 'worm.', 'ftp_write.',
         'guess_passwd.', 'imap.', 'multihop.', 'phf.', 'spy.', 'warezclient.', 'warezmaster.'], 'r2l.')
    test['Class'] = test['Class'].replace(['saint.', 'mscan.', 'ipsweep.', 'nmap.', 'portsweep.', 'satan.'], 'probe.')

    train_x, train_y, test_x, test_y = train_test(train, test)

    # Fit model
    classifier = GaussianNB()
    c = classifier.fit(train_x, train_y)

    # Predict training and test set results
    train_pred = c.predict(train_x)
    test_pred = c.predict(test_x)

    train_accuracy, test_accuracy = result(train_y, train_pred, test_y, test_pred)

    train_accuracy = round(train_accuracy*100, 2)
    test_accuracy = round(test_accuracy * 100, 2)

    return 'train: ', train_accuracy, ' test:', test_accuracy


def class_after():
    print("Gathering after classification")

    train_x, train_y, test_x, test_y = train_test(train, test)

    # Fit model
    classifier = GaussianNB()
    c = classifier.fit(train_x, train_y)

    # Predict training set results
    train_pred = pd.DataFrame(c.predict(train_x))
    train_y = pd.DataFrame(train_y)

    train_pred = train_pred.replace(['back.', 'land.', 'neptune.', 'pod.', 'smurf.', 'teardrop.'], 'dos.')
    train_pred = train_pred.replace(['buffer_overflow.', 'rootkit.', 'loadmodule.', 'perl.'], 'u2r.')
    train_pred = train_pred.replace(
        ['ftp_write.', 'guess_passwd.', 'imap.', 'multihop.', 'phf.', 'spy.', 'warezclient.', 'warezmaster.'], 'r2l.')
    train_pred = train_pred.replace(['ipsweep.', 'nmap.', 'portsweep.', 'satan.'], 'probe.')

    train_y = train_y.replace(['back.', 'land.', 'neptune.', 'pod.', 'smurf.', 'teardrop.'], 'dos.')
    train_y = train_y.replace(['buffer_overflow.', 'rootkit.', 'loadmodule.', 'perl.'], 'u2r.')
    train_y = train_y.replace(
        ['ftp_write.', 'guess_passwd.', 'imap.', 'multihop.', 'phf.', 'spy.', 'warezclient.', 'warezmaster.'], 'r2l.')
    train_y = train_y.replace(['ipsweep.', 'nmap.', 'portsweep.', 'satan.'], 'probe.')

    # Predict test set results
    test_pred = pd.DataFrame(c.predict(test_x))
    test_y = pd.DataFrame(test_y)

    test_pred = test_pred.replace(
        ['udpstorm.', 'processtable.', 'mailbomb.', 'apache2.', 'back.', 'land.', 'neptune.', 'pod.', 'smurf.',
         'teardrop.'], 'dos.')
    test_pred = test_pred.replace(
        ['httptunnel.', 'xterm.', 'sqlattack.', 'ps.', 'buffer_overflow.', 'rootkit.', 'loadmodule.', 'perl.'], 'u2r.')
    test_pred = test_pred.replace(
        ['xsnoop.', 'xlock.', 'sendmail.', 'named.', 'snmpgetattack.', 'snmpguess.', 'worm.', 'ftp_write.',
         'guess_passwd.', 'imap.', 'multihop.', 'phf.', 'spy.', 'warezclient.', 'warezmaster.'], 'r2l.')
    test_pred = test_pred.replace(['saint.', 'mscan.', 'ipsweep.', 'nmap.', 'portsweep.', 'satan.'], 'probe.')

    test_y = test_y.replace(
        ['udpstorm.', 'processtable.', 'mailbomb.', 'apache2.', 'back.', 'land.', 'neptune.', 'pod.', 'smurf.',
         'teardrop.'], 'dos.')
    test_y = test_y.replace(
        ['httptunnel.', 'xterm.', 'sqlattack.', 'ps.', 'buffer_overflow.', 'rootkit.', 'loadmodule.', 'perl.'], 'u2r.')
    test_y = test_y.replace(
        ['xsnoop.', 'xlock.', 'sendmail.', 'named.', 'snmpgetattack.', 'snmpguess.', 'worm.', 'ftp_write.',
         'guess_passwd.', 'imap.', 'multihop.', 'phf.', 'spy.', 'warezclient.', 'warezmaster.'], 'r2l.')
    test_y = test_y.replace(['saint.', 'mscan.', 'ipsweep.', 'nmap.', 'portsweep.', 'satan.'], 'probe.')

    train_accuracy, test_accuracy = result(train_y, train_pred, test_y, test_pred)

    train_accuracy = round(train_accuracy*100, 2)
    test_accuracy = round(test_accuracy*100, 2)

    return 'train:', train_accuracy, ' test:', test_accuracy


def result(train_y, train_pred, test_y, test_pred):
    train_accuracy = accuracy_score(train_y, train_pred)
    test_accuracy = accuracy_score(test_y, test_pred)

    # Confusion matrix
    labels = ['normal.', 'dos.', 'r2l.', 'u2r.', 'probe.']
    cm = confusion_matrix(test_y, test_pred, normalize='true', labels=['normal.', 'dos.', 'r2l.', 'u2r.', 'probe.'])

    for i in range(len(cm)):
        for j in range(len(cm)):
            cm[i][j] = cm[i][j] * 100

    df_cm = pd.DataFrame(cm, index=labels, columns=labels)
    sns.heatmap(df_cm, annot=True, cbar=True, linewidths=.5)
    plt.show()
    return train_accuracy, test_accuracy


def test_function(name):
    if name == 'before':
        return print(class_before())
    elif name == 'after':
        return print(class_after())
